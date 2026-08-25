//! Server capabilities: the set a server advertises, and the
//! CAPABILITY command asking for it again.
//!
//! Capabilities arrive unprompted three times ([RFC 5804 section 1.7]):
//! on connection, after a successful STARTTLS, and after an
//! authentication exchange that negotiated a security layer. They stay
//! static between those points, so a caller keeps the last set it saw
//! and only issues [`ManagesieveCapabilityGet`] when it wants a fresh
//! one, typically after authenticating, since OWNER and LANGUAGE are
//! per-user and MAXREDIRECTS may be too.
//!
//! A capability this crate does not model keeps its name and its value:
//! the specification asks clients to ignore what they do not
//! understand, not to refuse it, and the registry grows without this
//! crate.
//!
//! [RFC 5804 section 1.7]: https://www.rfc-editor.org/rfc/rfc5804#section-1.7
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_managesieve::{
//!     coroutine::{ManagesieveCoroutine, ManagesieveCoroutineState, ManagesieveYield},
//!     rfc5804::capability::ManagesieveCapabilityGet,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, greeting read)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveCapabilityGet::new();
//! let mut arg = None;
//!
//! let capabilities = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(capabilities)) => break capabilities,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{:?}", capabilities.sasl());
//! ```

use core::fmt;

use alloc::{string::String, vec::Vec};

use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*,
    managesieve_try,
    rfc5804::response::{ManagesieveCompletion, ManagesieveDataLine},
    send::*,
};

/// One capability line, a name and the value it may carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveCapability {
    /// The capability name, as the server spelled it.
    ///
    /// Names are case-insensitive, so a server is free to answer
    /// `IMPlemENTATION`; compare through
    /// [`ManagesieveCapabilities::has`] rather than on this field.
    pub name: String,
    /// The value, for the capabilities carrying one.
    pub value: Option<String>,
}

impl fmt::Display for ManagesieveCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{} {value}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// The capability set a server advertises.
///
/// The accessors below cover the capabilities [RFC 5804 section 1.7]
/// defines; anything else is reached through [`Self::value`] and
/// [`Self::has`], which is also how a capability registered after this
/// crate stays usable.
///
/// [RFC 5804 section 1.7]: https://www.rfc-editor.org/rfc/rfc5804#section-1.7
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveCapabilities {
    /// The capability lines, in the order the server sent them.
    pub capabilities: Vec<ManagesieveCapability>,
}

impl ManagesieveCapabilities {
    /// Reads a capability set out of the data lines of a response.
    ///
    /// A line the grammar does not fit is skipped rather than refused,
    /// since a client is asked to ignore what it does not understand
    /// and a malformed line is no reason to lose the rest of the set.
    pub fn parse(data: &[ManagesieveDataLine]) -> Self {
        let capabilities = data
            .iter()
            .filter_map(|line| {
                let name = String::from_utf8_lossy(line.string(0)?).into_owned();
                let value = line
                    .string(1)
                    .map(|value| String::from_utf8_lossy(value).into_owned());

                Some(ManagesieveCapability { name, value })
            })
            .collect();

        Self { capabilities }
    }

    /// The value of `name`, compared case-insensitively.
    ///
    /// Answers [`None`] both for a capability the server did not send
    /// and for one it sent without a value, which is what a valueless
    /// capability such as STARTTLS means; use [`Self::has`] to tell the
    /// two apart.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.capabilities
            .iter()
            .find(|capability| capability.name.eq_ignore_ascii_case(name))
            .and_then(|capability| capability.value.as_deref())
    }

    /// Whether `name` was advertised, compared case-insensitively.
    pub fn has(&self, name: &str) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.name.eq_ignore_ascii_case(name))
    }

    /// IMPLEMENTATION: the server name and version.
    pub fn implementation(&self) -> Option<&str> {
        self.value("IMPLEMENTATION")
    }

    /// VERSION: the protocol version, `1.0` for a server conforming to
    /// RFC 5804.
    ///
    /// Its absence means the server predates the specification, and
    /// with it the RENAMESCRIPT, CHECKSCRIPT and NOOP commands.
    pub fn version(&self) -> Option<&str> {
        self.value("VERSION")
    }

    /// SIEVE: the Sieve extensions the interpreter accepts in a
    /// `require` statement.
    pub fn sieve(&self) -> Vec<&str> {
        self.list("SIEVE")
    }

    /// SASL: the authentication mechanisms the server offers.
    ///
    /// An empty list on a cleartext connection means the server wants
    /// STARTTLS first, after which it advertises a real one.
    pub fn sasl(&self) -> Vec<&str> {
        self.list("SASL")
    }

    /// NOTIFY: the URI schemes the `enotify` Sieve extension can reach.
    pub fn notify(&self) -> Vec<&str> {
        self.list("NOTIFY")
    }

    /// STARTTLS: whether the server offers a TLS upgrade.
    ///
    /// A server drops the capability once TLS or authentication is in
    /// place, so a set read after either says nothing about what the
    /// server can do.
    pub fn starttls(&self) -> bool {
        self.has("STARTTLS")
    }

    /// UNAUTHENTICATE: whether the server can return to the
    /// non-authenticated state.
    pub fn unauthenticate(&self) -> bool {
        self.has("UNAUTHENTICATE")
    }

    /// MAXREDIRECTS: how many `redirect` actions one evaluation may
    /// perform.
    pub fn max_redirects(&self) -> Option<u32> {
        self.value("MAXREDIRECTS")?.parse().ok()
    }

    /// LANGUAGE: the language the human-readable texts come in.
    ///
    /// Its absence means `i-default`, and it may change once a user is
    /// authenticated.
    pub fn language(&self) -> Option<&str> {
        self.value("LANGUAGE")
    }

    /// OWNER: the canonical name of the authenticated user.
    ///
    /// Only sent once authentication succeeded, so it is also how a
    /// caller reads back the identity the server settled on.
    pub fn owner(&self) -> Option<&str> {
        self.value("OWNER")
    }

    /// Splits the value of `name` on spaces, for the capabilities
    /// carrying a list.
    fn list(&self, name: &str) -> Vec<&str> {
        self.value(name)
            .map(|value| value.split_whitespace().collect())
            .unwrap_or_default()
    }
}

impl fmt::Display for ManagesieveCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, capability) in self.capabilities.iter().enumerate() {
            if index > 0 {
                f.write_str("\n")?;
            }

            write!(f, "{capability}")?;
        }

        Ok(())
    }
}

/// The CAPABILITY command ([RFC 5804 section 2.4]).
///
/// [RFC 5804 section 2.4]: https://www.rfc-editor.org/rfc/rfc5804#section-2.4
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveCapabilityGetCommand;

impl From<ManagesieveCapabilityGetCommand> for Vec<u8> {
    fn from(_: ManagesieveCapabilityGetCommand) -> Vec<u8> {
        b"CAPABILITY\r\n".to_vec()
    }
}

/// Failure causes during the ManageSieve CAPABILITY exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveCapabilityGetError {
    /// The server refused the command.
    #[error("ManageSieve CAPABILITY failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve CAPABILITY failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve CAPABILITY coroutine.
pub struct ManagesieveCapabilityGet {
    state: State,
}

impl ManagesieveCapabilityGet {
    /// Creates the coroutine.
    pub fn new() -> Self {
        let send = ManagesieveCommandSend::new(ManagesieveCapabilityGetCommand);
        Self {
            state: State::Send(send),
        }
    }
}

impl Default for ManagesieveCapabilityGet {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveCapabilityGet {
    type Yield = ManagesieveYield;
    type Return = Result<ManagesieveCapabilities, ManagesieveCapabilityGetError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                let response = match out.response.into_result() {
                    Ok(response) => response,
                    Err(completion) => {
                        let err = ManagesieveCapabilityGetError::Rejected(completion);
                        return ManagesieveCoroutineState::Complete(Err(err));
                    }
                };

                let capabilities = ManagesieveCapabilities::parse(&response.data);
                debug!("capabilities read");

                ManagesieveCoroutineState::Complete(Ok(capabilities))
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveCapabilityGetCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send capability"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use crate::{
        coroutine::*,
        rfc5804::{
            capability::*,
            response::{ManagesieveDataLine, ManagesieveResponse, ManagesieveToken},
        },
        send::ManagesieveCommandSendError,
    };

    #[test]
    fn reads_every_capability_the_specification_defines() {
        let buf = b"\"IMPlemENTATION\" \"Example1 ManageSieved v001\"\r\n\
                    \"SASl\" \"PLAIN SCRAM-SHA-1\"\r\n\
                    \"SIeVE\" \"fileinto vacation\"\r\n\
                    \"StaRTTLS\"\r\n\
                    \"NOTIFY\" \"xmpp mailto\"\r\n\
                    \"MAXREdIRECTS\" \"5\"\r\n\
                    \"LANGUAGE\" \"ru\"\r\n\
                    \"OWNER\" \"alexey@example.com\"\r\n\
                    \"UNAUTHENTICATE\"\r\n\
                    \"VERSION\" \"1.0\"\r\n\
                    OK\r\n";

        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();
        let capabilities = ManagesieveCapabilities::parse(&response.data);

        assert_eq!(
            capabilities.implementation().unwrap(),
            "Example1 ManageSieved v001"
        );
        assert_eq!(capabilities.version().unwrap(), "1.0");
        assert_eq!(capabilities.sasl(), vec!["PLAIN", "SCRAM-SHA-1"]);
        assert_eq!(capabilities.sieve(), vec!["fileinto", "vacation"]);
        assert_eq!(capabilities.notify(), vec!["xmpp", "mailto"]);
        assert_eq!(capabilities.max_redirects(), Some(5));
        assert_eq!(capabilities.language().unwrap(), "ru");
        assert_eq!(capabilities.owner().unwrap(), "alexey@example.com");
        assert!(capabilities.starttls());
        assert!(capabilities.unauthenticate());
    }

    #[test]
    fn answers_nothing_for_what_the_server_left_out() {
        let capabilities = ManagesieveCapabilities::default();

        assert!(capabilities.implementation().is_none());
        assert!(capabilities.version().is_none());
        assert!(capabilities.language().is_none());
        assert!(capabilities.owner().is_none());
        assert!(capabilities.max_redirects().is_none());
        assert!(capabilities.sasl().is_empty());
        assert!(capabilities.sieve().is_empty());
        assert!(capabilities.notify().is_empty());
        assert!(!capabilities.starttls());
        assert!(!capabilities.unauthenticate());
        assert!(!capabilities.has("SIEVE"));
    }

    #[test]
    fn skips_a_line_opening_on_something_other_than_a_name() {
        let data = vec![
            ManagesieveDataLine {
                tokens: vec![ManagesieveToken::Atom(String::from("ACTIVE"))],
            },
            ManagesieveDataLine {
                tokens: vec![
                    ManagesieveToken::String(b"SIEVE".to_vec()),
                    ManagesieveToken::String(b"fileinto".to_vec()),
                ],
            },
        ];

        let capabilities = ManagesieveCapabilities::parse(&data);

        assert_eq!(capabilities.to_string(), "SIEVE fileinto");
        assert!(capabilities.max_redirects().is_none());
    }

    #[test]
    fn ignores_a_maxredirects_that_is_not_a_number() {
        let buf = b"\"MAXREDIRECTS\" \"many\"\r\nOK\r\n";
        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();
        let capabilities = ManagesieveCapabilities::parse(&response.data);

        assert!(capabilities.max_redirects().is_none());
    }

    #[test]
    fn success_returns_the_capabilities() {
        let mut capability = ManagesieveCapabilityGet::new();

        let bytes = expect_wants_write(&mut capability, None);
        assert_eq!(bytes, b"CAPABILITY\r\n");

        expect_wants_read(&mut capability);

        let reply = b"\"SIEVE\" \"fileinto\"\r\nOK\r\n";
        let capabilities = expect_complete_ok(&mut capability, reply);
        assert_eq!(capabilities.sieve(), vec!["fileinto"]);
    }

    #[test]
    fn rejection_returns_rejected_error() {
        let mut capability = ManagesieveCapabilityGet::new();
        expect_wants_write(&mut capability, None);
        expect_wants_read(&mut capability);

        let err = expect_complete_err(&mut capability, b"NO \"not now\"\r\n");
        let ManagesieveCapabilityGetError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };
        assert_eq!(completion.to_string(), "NO not now");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut capability = ManagesieveCapabilityGet::new();
        expect_wants_write(&mut capability, None);
        expect_wants_read(&mut capability);

        let err = expect_complete_err(&mut capability, b"");
        assert!(matches!(
            err,
            ManagesieveCapabilityGetError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveCapabilityGet, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveCapabilityGet) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ManagesieveCapabilityGet,
        reply: &[u8],
    ) -> ManagesieveCapabilities {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(capabilities)) => capabilities,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveCapabilityGet,
        reply: &[u8],
    ) -> ManagesieveCapabilityGetError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
