//! Composite session-opening coroutine: everything between a bare
//! address and an authenticated ManageSieve session.
//!
//! The handshake is where the protocol knowledge accumulates: which
//! transport a scheme implies, that the greeting carries the
//! capabilities rather than a banner, that STARTTLS is only offered on
//! a cleartext transport, that the capabilities are re-read once TLS is
//! up rather than carried across, and which mechanisms may not travel
//! in the clear. Holding all of that in a std client would put it out
//! of reach of every other runtime, so it lives here as a coroutine
//! instead.
//!
//! Unlike a command coroutine, [`ManagesieveSessionOpen`] yields
//! transport requests as well as reads and writes: connect this socket,
//! upgrade that one to TLS. The caller answers them with whatever
//! sockets its runtime has, and inherits the ordering for free. A
//! caller that skips a step cannot advance, because the state machine
//! never asks for the next one.
//!
//! ManageSieve has no pre-authenticated greeting, so authentication is
//! skipped only when no mechanism is given, which is what a local
//! socket reaching an already-authenticated proxy wants.
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
//!     coroutine::{ManagesieveCoroutine, ManagesieveCoroutineState},
//!     session::{
//!         ManagesieveSessionOpen, ManagesieveSessionOpenOptions, ManagesieveSessionOpenYield,
//!         ManagesieveSessionTransport,
//!     },
//! };
//! use io_sasl::rfc4616::plain::SaslPlainCreds;
//!
//! let transport = ManagesieveSessionTransport::Tcp {
//!     host: String::from("localhost"),
//!     port: 4190,
//! };
//!
//! let sasl = SaslPlainCreds {
//!     authzid: None,
//!     authcid: String::from("alice"),
//!     passwd: String::from("secret").into(),
//! };
//!
//! let opts = ManagesieveSessionOpenOptions {
//!     allow_cleartext_auth: true,
//!     ..Default::default()
//! };
//!
//! let mut coroutine = ManagesieveSessionOpen::new(transport, Some(sasl), opts);
//!
//! let mut stream: Option<TcpStream> = None;
//! let mut buf = [0u8; 4096];
//! let mut arg = None;
//!
//! let session = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsTcpConnect {
//!             host,
//!             port,
//!         }) => {
//!             stream = Some(TcpStream::connect((host.as_str(), port)).unwrap());
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(bytes)) => {
//!             stream.as_mut().unwrap().write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsRead) => {
//!             let n = stream.as_mut().unwrap().read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Yielded(yielded) => panic!("unexpected {yielded:?}"),
//!         ManagesieveCoroutineState::Complete(Ok(session)) => break session,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{}", session.capabilities);
//! ```

use core::fmt;

use alloc::{boxed::Box, string::String, vec::Vec};

use io_sasl::mechanism::{Sasl, SaslMechanism};
use log::debug;
use thiserror::Error;
#[cfg(feature = "url")]
use url::Url;

use crate::{
    coroutine::*,
    managesieve_try,
    rfc5804::{authenticate::*, capability::ManagesieveCapabilities, greeting::*, starttls::*},
};

/// The port IANA reserved for ManageSieve.
///
/// The specification registers one port and no implicit-TLS twin, so
/// the same number serves `sieve://` and `sieves://` alike.
pub const DEFAULT_PORT: u16 = 4190;

/// Failure causes while opening a ManageSieve session.
#[derive(Debug, Error)]
pub enum ManagesieveSessionOpenError {
    /// STARTTLS was requested on a transport that is already TLS.
    #[error("STARTTLS requested on an already-encrypted transport: TLS is active")]
    StartTlsOverTls,
    /// STARTTLS was requested and the server does not offer it.
    ///
    /// Carrying on would open the session in the clear, which is what
    /// asking for STARTTLS says the caller will not accept.
    #[error("STARTTLS requested and the server does not advertise it")]
    StartTlsUnsupported,
    /// Credentials that a passive observer could reuse were about to
    /// travel over a cleartext connection.
    ///
    /// PLAIN and LOGIN send the password, OAUTHBEARER and XOAUTH2 send
    /// a bearer token, and RFC 5804 section 5 asks implementations to
    /// carry a configuration where such mechanisms cannot be used
    /// without an encryption layer. That configuration is the default
    /// here; see
    /// [`ManagesieveSessionOpenOptions::allow_cleartext_auth`].
    #[error("{} SASL mechanism refuses to travel over a cleartext connection", .0.as_str())]
    CleartextAuth(SaslMechanism),
    /// The URL carries no host to connect to.
    #[cfg(feature = "url")]
    #[error("ManageSieve URL `{0}` has no host")]
    UrlMissingHost(String),
    /// The URL scheme is none of sieve, sieves and unix.
    #[cfg(feature = "url")]
    #[error(
        "ManageSieve URL `{0}` has unsupported scheme `{1}` (expected `sieve`, `sieves` or `unix`)"
    )]
    UrlUnsupportedScheme(String, String),
    /// The greeting coroutine failed.
    #[error(transparent)]
    Greeting(#[from] ManagesieveGreetingGetError),
    /// The STARTTLS coroutine failed.
    #[error(transparent)]
    StartTls(#[from] ManagesieveStartTlsError),
    /// The AUTHENTICATE coroutine failed.
    #[error(transparent)]
    Authenticate(#[from] ManagesieveAuthenticateError),
}

/// Where and how the connection is opened.
///
/// The scheme table that maps a ManageSieve URL onto one of these
/// variants is protocol knowledge, so it lives here rather than in the
/// transport layer; see [`ManagesieveSessionTransport::from_url`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagesieveSessionTransport {
    /// Plain TCP, the `sieve://` scheme. Pair it with
    /// [`ManagesieveSessionOpenOptions::starttls`] to reach a TLS
    /// session.
    Tcp {
        /// The server host name.
        host: String,
        /// The server port, conventionally 4190.
        port: u16,
    },
    /// Implicit TLS, the `sieves://` scheme.
    ///
    /// The specification registers no such scheme, STARTTLS being the
    /// upgrade path it defines; the name is this project's, for the
    /// deployments listening for a TLS handshake straight away.
    Tls {
        /// The server host name.
        host: String,
        /// The server port, conventionally 4190 here too.
        port: u16,
    },
    /// A local unix domain socket, the `unix://` scheme, typically a
    /// pre-authenticated socket proxy.
    Unix(String),
}

impl ManagesieveSessionTransport {
    /// Whether the transport protects what travels over it before any
    /// upgrade.
    ///
    /// A local socket counts: it does not cross a network, and the
    /// proxy behind it is what the caller pointed at.
    fn is_protected(&self) -> bool {
        !matches!(self, Self::Tcp { .. })
    }
}

#[cfg(feature = "url")]
impl ManagesieveSessionTransport {
    /// Reads the transport out of a ManageSieve URL.
    ///
    /// `sieve://` is plain TCP, `sieves://` is implicit TLS and
    /// `unix://` is a local socket path; both network schemes default
    /// to port 4190, and an explicit port in the URL wins.
    pub fn from_url(url: &Url) -> Result<Self, ManagesieveSessionOpenError> {
        let scheme = url.scheme();

        if scheme.eq_ignore_ascii_case("unix") {
            return Ok(Self::Unix(String::from(url.path())));
        }

        let Some(host) = url.host_str() else {
            let url = String::from(url.as_str());
            return Err(ManagesieveSessionOpenError::UrlMissingHost(url));
        };

        let host = String::from(host);
        let port = url.port().unwrap_or(DEFAULT_PORT);

        if scheme.eq_ignore_ascii_case("sieve") {
            Ok(Self::Tcp { host, port })
        } else if scheme.eq_ignore_ascii_case("sieves") {
            Ok(Self::Tls { host, port })
        } else {
            let scheme = String::from(scheme);
            let url = String::from(url.as_str());
            Err(ManagesieveSessionOpenError::UrlUnsupportedScheme(
                url, scheme,
            ))
        }
    }
}

/// Policy options for [`ManagesieveSessionOpen::new`].
///
/// The default upgrades nothing and refuses to send a reusable
/// credential in the clear, which is what an implicit-TLS transport and
/// a local socket proxy both want unchanged.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveSessionOpenOptions {
    /// Whether to upgrade the connection with STARTTLS after the
    /// greeting. Only valid on a cleartext transport, since
    /// [`ManagesieveSessionTransport::Tls`] is already encrypted.
    pub starttls: bool,
    /// Whether a mechanism disclosing a reusable credential may run
    /// over a cleartext connection.
    ///
    /// PLAIN, LOGIN, OAUTHBEARER and XOAUTH2 hand a passive observer
    /// something it can replay, so the session refuses them by default
    /// and RFC 5804 section 5 asks for exactly that configuration.
    /// SCRAM and CRAM-MD5 disclose no password and are unaffected, and
    /// so are ANONYMOUS and EXTERNAL, which send no credential at all.
    pub allow_cleartext_auth: bool,
}

/// An opened ManageSieve session.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveSessionOpenData {
    /// The capabilities the server last reported: after
    /// authentication when there was one, after the TLS upgrade
    /// otherwise, and the greeting's when neither happened.
    pub capabilities: ManagesieveCapabilities,
}

/// Requests emitted while opening a session.
///
/// The three connect variants and the upgrade are what set this
/// coroutine apart from a command coroutine: the caller answers them
/// with its own sockets, whatever the runtime.
#[derive(Debug)]
pub enum ManagesieveSessionOpenYield {
    /// The caller opens a plain TCP connection and resumes.
    WantsTcpConnect {
        /// The server host name.
        host: String,
        /// The server port.
        port: u16,
    },
    /// The caller opens a TLS connection and resumes.
    WantsTlsConnect {
        /// The server host name, also the certificate name to verify.
        host: String,
        /// The server port.
        port: u16,
    },
    /// The caller connects to the unix socket at this path and resumes.
    WantsUnixConnect(String),
    /// The caller upgrades the open connection to TLS and resumes.
    ///
    /// Emitted only once the STARTTLS exchange completed cleanly; the
    /// coroutine refuses the upgrade itself when the server appended
    /// bytes to its OK.
    WantsTlsUpgrade,
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
}

impl From<ManagesieveYield> for ManagesieveSessionOpenYield {
    fn from(yielded: ManagesieveYield) -> Self {
        match yielded {
            ManagesieveYield::WantsRead => Self::WantsRead,
            ManagesieveYield::WantsWrite(bytes) => Self::WantsWrite(bytes),
        }
    }
}

/// I/O-free ManageSieve session-opening coroutine.
pub struct ManagesieveSessionOpen {
    state: State,
    transport: ManagesieveSessionTransport,
    sasl: Option<Sasl>,
    capabilities: ManagesieveCapabilities,
    upgraded: bool,
    opts: ManagesieveSessionOpenOptions,
}

impl ManagesieveSessionOpen {
    /// Builds a session-opening coroutine reaching `transport` and
    /// authenticating with `sasl`.
    ///
    /// `sasl` of [`None`] stops after the greeting, which is what a
    /// pre-authenticated socket proxy wants. A SCRAM exchange draws
    /// nothing here: its client nonce travels with the credentials, so
    /// this coroutine stays free of both I/O and randomness.
    pub fn new(
        transport: ManagesieveSessionTransport,
        sasl: Option<impl Into<Sasl>>,
        opts: ManagesieveSessionOpenOptions,
    ) -> Self {
        Self {
            state: State::Connect,
            transport,
            sasl: sasl.map(Into::into),
            capabilities: ManagesieveCapabilities::default(),
            upgraded: false,
            opts,
        }
    }

    /// Builds the authentication step, or reports there is nothing to
    /// authenticate.
    ///
    /// The initial response goes inline: RFC 5804 section 2.1 carries
    /// one unconditionally, unlike IMAP where a capability gates it, so
    /// there is no server this costs a round trip against. A caller
    /// wanting the conservative flow drives
    /// [`ManagesieveAuthenticate`] itself.
    fn wants_auth(&mut self) -> Result<Option<State>, ManagesieveSessionOpenError> {
        let Some(sasl) = self.sasl.take() else {
            return Ok(None);
        };

        let mechanism = sasl.mechanism();
        let protected = self.upgraded || self.transport.is_protected();

        if !protected && !self.opts.allow_cleartext_auth && discloses_credential(mechanism) {
            return Err(ManagesieveSessionOpenError::CleartextAuth(mechanism));
        }

        let opts = ManagesieveAuthenticateOptions {
            initial_response: true,
            ensure_capabilities: true,
        };

        let auth = ManagesieveAuthenticate::new(sasl, opts);

        Ok(Some(State::Auth(Box::new(auth))))
    }

    /// Terminal value, taking the capabilities observed along the way.
    fn complete(
        &mut self,
    ) -> ManagesieveCoroutineState<
        ManagesieveSessionOpenYield,
        <Self as ManagesieveCoroutine>::Return,
    > {
        let data = ManagesieveSessionOpenData {
            capabilities: core::mem::take(&mut self.capabilities),
        };

        ManagesieveCoroutineState::Complete(Ok(data))
    }
}

impl ManagesieveCoroutine for ManagesieveSessionOpen {
    type Yield = ManagesieveSessionOpenYield;
    type Return = Result<ManagesieveSessionOpenData, ManagesieveSessionOpenError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Connect => {
                    if self.opts.starttls && self.transport.is_protected() {
                        let err = ManagesieveSessionOpenError::StartTlsOverTls;
                        return ManagesieveCoroutineState::Complete(Err(err));
                    }

                    // NOTE: the transport is small and read once per
                    // session, so cloning it out beats threading an
                    // Option through the whole state machine.
                    let yielded = match &self.transport {
                        ManagesieveSessionTransport::Tcp { host, port } => {
                            ManagesieveSessionOpenYield::WantsTcpConnect {
                                host: host.clone(),
                                port: *port,
                            }
                        }
                        ManagesieveSessionTransport::Tls { host, port } => {
                            ManagesieveSessionOpenYield::WantsTlsConnect {
                                host: host.clone(),
                                port: *port,
                            }
                        }
                        ManagesieveSessionTransport::Unix(path) => {
                            ManagesieveSessionOpenYield::WantsUnixConnect(path.clone())
                        }
                    };

                    self.state = State::Greeting(ManagesieveGreetingGet::new());
                    debug!("{}", self.state);

                    return ManagesieveCoroutineState::Yielded(yielded);
                }
                State::Greeting(greeting) => {
                    self.capabilities = managesieve_try!(greeting, arg);

                    if self.opts.starttls {
                        if !self.capabilities.starttls() {
                            let err = ManagesieveSessionOpenError::StartTlsUnsupported;
                            return ManagesieveCoroutineState::Complete(Err(err));
                        }

                        self.state = State::StartTls(ManagesieveStartTls::new());
                        debug!("{}", self.state);
                        continue;
                    }

                    match self.wants_auth() {
                        Err(err) => return ManagesieveCoroutineState::Complete(Err(err)),
                        Ok(None) => return self.complete(),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                    }
                }
                State::StartTls(starttls) => {
                    managesieve_try!(starttls, arg);

                    self.upgraded = true;
                    self.state = State::Upgraded;
                    debug!("{}", self.state);

                    return ManagesieveCoroutineState::Yielded(
                        ManagesieveSessionOpenYield::WantsTlsUpgrade,
                    );
                }
                State::Upgraded => {
                    // NOTE: RFC 5804 section 2.2 invalidates the
                    // pre-upgrade capability list and has the server
                    // send a fresh one over TLS, which is the same
                    // response the greeting reads.
                    self.state = State::GreetingTls(ManagesieveGreetingGet::new());
                    debug!("{}", self.state);
                }
                State::GreetingTls(greeting) => {
                    self.capabilities = managesieve_try!(greeting, arg);

                    match self.wants_auth() {
                        Err(err) => return ManagesieveCoroutineState::Complete(Err(err)),
                        Ok(None) => return self.complete(),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                    }
                }
                State::Auth(auth) => {
                    self.capabilities = managesieve_try!(auth.as_mut(), arg);
                    return self.complete();
                }
            }
        }
    }
}

/// Default ALPN protocol identifiers offered for a ManageSieve TLS
/// handshake.
///
/// The list is empty on purpose: no ALPN identifier is registered for
/// ManageSieve, and offering an invented one gets the handshake refused
/// by a server that checks. Callers whose server wants a private
/// identifier set it themselves.
pub fn default_alpn() -> Vec<String> {
    Vec::new()
}

/// The default ManageSieve port, 4190 whatever the scheme.
pub fn default_port(_scheme: &str) -> u16 {
    DEFAULT_PORT
}

/// Whether a mechanism hands a passive observer something it can
/// replay.
///
/// PLAIN and LOGIN send the password itself, and the two OAuth
/// mechanisms send a bearer token, which is a password with an expiry.
/// The rest either prove a secret without disclosing it or carry no
/// credential at all.
fn discloses_credential(mechanism: SaslMechanism) -> bool {
    matches!(
        mechanism,
        SaslMechanism::Plain
            | SaslMechanism::Login
            | SaslMechanism::OAuthBearer
            | SaslMechanism::XOAuth2
    )
}

enum State {
    Connect,
    Greeting(ManagesieveGreetingGet),
    StartTls(ManagesieveStartTls),
    Upgraded,
    GreetingTls(ManagesieveGreetingGet),
    // NOTE: boxed because a mechanism holding its own credentials
    // dwarfs every other state, and the enum is as large as its largest
    // variant for the whole session.
    Auth(Box<ManagesieveAuthenticate>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("open connection"),
            Self::Greeting(_) => f.write_str("read greeting"),
            Self::StartTls(_) => f.write_str("send starttls"),
            Self::Upgraded => f.write_str("connection upgraded to tls"),
            Self::GreetingTls(_) => f.write_str("read greeting over tls"),
            Self::Auth(_) => f.write_str("authenticate"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use io_sasl::{
        login::SaslLoginCreds, rfc4505::anonymous::SaslAnonymousCreds,
        rfc4616::plain::SaslPlainCreds, rfc7628::oauthbearer::SaslOauthbearerCreds,
        xoauth2::SaslXoauth2Creds,
    };
    use secrecy::SecretString;

    use crate::session::*;

    #[test]
    fn tcp_transport_yields_tcp_connect_then_reads_the_greeting() {
        let mut session = open(tcp(), None, Default::default());

        match session.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsTcpConnect {
                host,
                port,
            }) => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 4190);
            }
            state => panic!("expected WantsTcpConnect, got {state:?}"),
        }

        match session.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        let greeting = b"\"IMPLEMENTATION\" \"Example1\"\r\n\"VERSION\" \"1.0\"\r\nOK\r\n";
        match session.resume(Some(greeting)) {
            ManagesieveCoroutineState::Complete(Ok(data)) => {
                assert_eq!(data.capabilities.version().unwrap(), "1.0");
            }
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn unix_transport_yields_unix_connect() {
        let transport = ManagesieveSessionTransport::Unix("/run/sieve.sock".to_string());
        let mut session = open(transport, None, Default::default());

        match session.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsUnixConnect(
                path,
            )) => assert_eq!(path, "/run/sieve.sock"),
            state => panic!("expected WantsUnixConnect, got {state:?}"),
        }
    }

    #[test]
    fn starttls_over_tls_fails_before_opening_a_socket() {
        let transport = ManagesieveSessionTransport::Tls {
            host: "localhost".to_string(),
            port: 4190,
        };

        let opts = ManagesieveSessionOpenOptions {
            starttls: true,
            ..Default::default()
        };

        let mut session = open(transport, None, opts);

        match session.resume(None) {
            ManagesieveCoroutineState::Complete(Err(
                ManagesieveSessionOpenError::StartTlsOverTls,
            )) => {}
            state => panic!("expected StartTlsOverTls, got {state:?}"),
        }
    }

    #[test]
    fn starttls_against_a_server_without_it_refuses_the_session() {
        let opts = ManagesieveSessionOpenOptions {
            starttls: true,
            ..Default::default()
        };

        let mut session = open(tcp(), None, opts);
        session.resume(None);
        session.resume(None);

        match session.resume(Some(b"\"SIEVE\" \"fileinto\"\r\nOK\r\n")) {
            ManagesieveCoroutineState::Complete(Err(
                ManagesieveSessionOpenError::StartTlsUnsupported,
            )) => {}
            state => panic!("expected StartTlsUnsupported, got {state:?}"),
        }
    }

    #[test]
    fn starttls_reaches_the_upgrade_then_reads_the_new_capabilities() {
        let opts = ManagesieveSessionOpenOptions {
            starttls: true,
            ..Default::default()
        };

        let mut session = open(tcp(), None, opts);
        session.resume(None);
        session.resume(None);

        let command = match session.resume(Some(b"\"STARTTLS\"\r\nOK\r\n")) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(bytes)) => {
                bytes
            }
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        assert_eq!(command, b"STARTTLS\r\n");

        session.resume(None);

        match session.resume(Some(b"OK\r\n")) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsTlsUpgrade) => {}
            state => panic!("expected WantsTlsUpgrade, got {state:?}"),
        }

        // NOTE: the caller has swapped in the TLS stream; the server now
        // re-issues its capabilities rather than the client trusting
        // the cleartext ones.
        match session.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        match session.resume(Some(b"\"SASL\" \"PLAIN\"\r\nOK\r\n")) {
            ManagesieveCoroutineState::Complete(Ok(data)) => {
                assert_eq!(data.capabilities.sasl(), ["PLAIN"]);
                assert!(!data.capabilities.starttls());
            }
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn plain_over_cleartext_is_refused_and_allowed_on_demand() {
        let mut session = open(tcp(), Some(plain()), Default::default());
        session.resume(None);
        session.resume(None);

        match session.resume(Some(b"\"SASL\" \"PLAIN\"\r\nOK\r\n")) {
            ManagesieveCoroutineState::Complete(Err(
                ManagesieveSessionOpenError::CleartextAuth(SaslMechanism::Plain),
            )) => {}
            state => panic!("expected CleartextAuth, got {state:?}"),
        }

        let opts = ManagesieveSessionOpenOptions {
            allow_cleartext_auth: true,
            ..Default::default()
        };

        let mut session = open(tcp(), Some(plain()), opts);
        session.resume(None);
        session.resume(None);

        let command = match session.resume(Some(b"\"SASL\" \"PLAIN\"\r\nOK\r\n")) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(bytes)) => {
                bytes
            }
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        assert_eq!(
            command,
            b"AUTHENTICATE \"PLAIN\" \"AGFsaWNlAHNlY3JldA==\"\r\n"
        );
    }

    #[test]
    fn every_mechanism_disclosing_a_credential_is_refused_over_cleartext() {
        let replayable: Vec<Sasl> = vec![
            plain(),
            SaslLoginCreds {
                username: "alice".to_string(),
                password: SecretString::from("secret"),
            }
            .into(),
            SaslOauthbearerCreds {
                username: "alice".to_string(),
                host: "localhost".to_string(),
                port: 4190,
                token: SecretString::from("vF9dft4qmT"),
            }
            .into(),
            SaslXoauth2Creds {
                username: "alice".to_string(),
                token: SecretString::from("vF9dft4qmT"),
            }
            .into(),
        ];

        for sasl in replayable {
            let mechanism = sasl.mechanism();
            let mut session = open(tcp(), Some(sasl), Default::default());
            session.resume(None);
            session.resume(None);

            match session.resume(Some(b"OK\r\n")) {
                ManagesieveCoroutineState::Complete(Err(
                    ManagesieveSessionOpenError::CleartextAuth(refused),
                )) => assert_eq!(refused, mechanism),
                state => panic!("expected CleartextAuth for {mechanism:?}, got {state:?}"),
            }
        }

        // NOTE: ANONYMOUS carries no credential at all, so nothing is
        // disclosed and the session carries on.
        let anonymous = SaslAnonymousCreds { message: None }.into();
        let mut session = open(tcp(), Some(anonymous), Default::default());
        session.resume(None);
        session.resume(None);

        match session.resume(Some(b"OK\r\n")) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(_)) => {}
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    #[test]
    fn a_protected_transport_carries_plain_without_asking() {
        let transport = ManagesieveSessionTransport::Unix("/run/sieve.sock".to_string());
        let mut session = open(transport, Some(plain()), Default::default());

        session.resume(None);
        session.resume(None);

        match session.resume(Some(b"\"SASL\" \"PLAIN\"\r\nOK\r\n")) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(_)) => {}
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    #[cfg(feature = "url")]
    #[test]
    fn urls_map_onto_transports() {
        let url = Url::parse("sieve://example.org").unwrap();
        let expected = ManagesieveSessionTransport::Tcp {
            host: "example.org".to_string(),
            port: 4190,
        };
        assert_eq!(
            ManagesieveSessionTransport::from_url(&url).unwrap(),
            expected
        );

        let url = Url::parse("sieves://example.org:5190").unwrap();
        let expected = ManagesieveSessionTransport::Tls {
            host: "example.org".to_string(),
            port: 5190,
        };
        assert_eq!(
            ManagesieveSessionTransport::from_url(&url).unwrap(),
            expected
        );

        let url = Url::parse("unix:///run/sieve.sock").unwrap();
        let expected = ManagesieveSessionTransport::Unix("/run/sieve.sock".to_string());
        assert_eq!(
            ManagesieveSessionTransport::from_url(&url).unwrap(),
            expected
        );

        let url = Url::parse("http://example.org").unwrap();
        let err = ManagesieveSessionTransport::from_url(&url).unwrap_err();
        assert!(matches!(
            err,
            ManagesieveSessionOpenError::UrlUnsupportedScheme(_, _)
        ));

        let url = Url::parse("sieve://").unwrap();
        let err = ManagesieveSessionTransport::from_url(&url).unwrap_err();
        assert!(matches!(
            err,
            ManagesieveSessionOpenError::UrlMissingHost(_)
        ));
    }

    #[test]
    fn the_default_port_ignores_the_scheme_and_alpn_stays_empty() {
        assert_eq!(default_port("sieve"), 4190);
        assert_eq!(default_port("sieves"), 4190);
        assert!(default_alpn().is_empty());
    }

    fn tcp() -> ManagesieveSessionTransport {
        ManagesieveSessionTransport::Tcp {
            host: "localhost".to_string(),
            port: 4190,
        }
    }

    fn plain() -> Sasl {
        SaslPlainCreds {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: SecretString::from("secret"),
        }
        .into()
    }

    fn open(
        transport: ManagesieveSessionTransport,
        sasl: Option<Sasl>,
        opts: ManagesieveSessionOpenOptions,
    ) -> ManagesieveSessionOpen {
        ManagesieveSessionOpen::new(transport, sasl, opts)
    }
}
