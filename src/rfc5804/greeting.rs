//! The server greeting: the capability set a ManageSieve server sends
//! the moment a connection opens, and again once TLS is in place.
//!
//! Nothing is written first, so this is a read-only coroutine ([RFC
//! 5804 section 1.1]). It is also what reads the second capability
//! response, the one following a STARTTLS upgrade, since the two are
//! the same bytes on the wire and the same meaning: this is the server,
//! and this is what it can do.
//!
//! The greeting is refused when the server appends anything to it,
//! because a client is about to decide whether to upgrade to TLS and
//! bytes riding in the same segment would be replayed inside that
//! session. Nothing legitimate follows a greeting: the protocol answers
//! one command with one response, and the client has not spoken yet.
//!
//! [RFC 5804 section 1.1]: https://www.rfc-editor.org/rfc/rfc5804#section-1.1
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
//!     rfc5804::greeting::ManagesieveGreetingGet,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated when implicit)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveGreetingGet::new();
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
//! println!("{}", capabilities);
//! ```

use core::fmt;

use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*,
    managesieve_try,
    rfc5804::{
        capability::ManagesieveCapabilities,
        response::{ManagesieveCompletion, ManagesieveStatus},
    },
    send::*,
};

/// Failure causes while reading a ManageSieve greeting.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveGreetingGetError {
    /// The server greeted with NO or BYE, refusing the connection.
    #[error("ManageSieve greeting failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The server sent bytes past the greeting.
    ///
    /// Nothing follows a greeting, so their presence means an attacker
    /// injected commands the server would replay inside the TLS session
    /// a STARTTLS upgrade is about to open.
    #[error("ManageSieve greeting carried trailing bytes: refusing the session")]
    Injection,
    /// The underlying read failed.
    #[error("ManageSieve greeting failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve greeting coroutine.
pub struct ManagesieveGreetingGet {
    state: State,
}

impl ManagesieveGreetingGet {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Read(ManagesieveResponseRead::new()),
        }
    }
}

impl Default for ManagesieveGreetingGet {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveGreetingGet {
    type Yield = ManagesieveYield;
    type Return = Result<ManagesieveCapabilities, ManagesieveGreetingGetError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Read(read) => {
                let out = managesieve_try!(read, arg);

                if !out.trailing.is_empty() {
                    let err = ManagesieveGreetingGetError::Injection;
                    return ManagesieveCoroutineState::Complete(Err(err));
                }

                if out.response.completion.status != ManagesieveStatus::Ok {
                    let err = ManagesieveGreetingGetError::Rejected(out.response.completion);
                    return ManagesieveCoroutineState::Complete(Err(err));
                }

                let capabilities = ManagesieveCapabilities::parse(&out.response.data);
                debug!("greeting read");

                ManagesieveCoroutineState::Complete(Ok(capabilities))
            }
        }
    }
}

enum State {
    Read(ManagesieveResponseRead),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(_) => f.write_str("read greeting"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::{coroutine::*, rfc5804::greeting::*};

    #[test]
    fn success_returns_the_capabilities() {
        let mut greeting = ManagesieveGreetingGet::new();

        expect_wants_read(&mut greeting);

        let reply = b"\"IMPLEMENTATION\" \"Example1\"\r\n\"STARTTLS\"\r\nOK\r\n";
        let capabilities = expect_complete_ok(&mut greeting, reply);

        assert_eq!(capabilities.implementation().unwrap(), "Example1");
        assert!(capabilities.starttls());
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut greeting = ManagesieveGreetingGet::new();
        expect_wants_read(&mut greeting);

        let reply = b"BYE \"Too many connections\"\r\n";
        let err = expect_complete_err(&mut greeting, reply);
        let ManagesieveGreetingGetError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "BYE Too many connections");
    }

    #[test]
    fn trailing_bytes_return_injection_error() {
        let mut greeting = ManagesieveGreetingGet::new();
        expect_wants_read(&mut greeting);

        // NOTE: the injected command rides in the same segment as the
        // greeting, so the server would replay it once TLS is up.
        let err = expect_complete_err(&mut greeting, b"OK\r\nNOOP\r\n");
        assert_eq!(err, ManagesieveGreetingGetError::Injection);
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut greeting = ManagesieveGreetingGet::new();
        expect_wants_read(&mut greeting);

        let err = expect_complete_err(&mut greeting, b"");
        assert!(matches!(
            err,
            ManagesieveGreetingGetError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_read(cor: &mut ManagesieveGreetingGet) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ManagesieveGreetingGet,
        reply: &[u8],
    ) -> ManagesieveCapabilities {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(capabilities)) => capabilities,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveGreetingGet,
        reply: &[u8],
    ) -> ManagesieveGreetingGetError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
