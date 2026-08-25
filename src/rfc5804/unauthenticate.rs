//! The UNAUTHENTICATE command, returning a session to the
//! non-authenticated state ([RFC 5804 section 2.14.1]).
//!
//! An extension rather than the core protocol, advertised as the
//! UNAUTHENTICATE capability. It is what lets one connection serve
//! several users in turn, since reauthenticating over an authenticated
//! session is otherwise forbidden. Any TLS or SASL security layer stays
//! in place, and the capabilities are re-read afterwards, OWNER and
//! LANGUAGE being per-user.
//!
//! [RFC 5804 section 2.14.1]: https://www.rfc-editor.org/rfc/rfc5804#section-2.14.1
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
//!     rfc5804::unauthenticate::ManagesieveUnauthenticate,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveUnauthenticate::new();
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(())) => break,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::fmt;

use alloc::vec::Vec;

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, managesieve_try, rfc5804::response::ManagesieveCompletion, send::*};

/// The UNAUTHENTICATE command ([RFC 5804 section 2.14.1]).
///
/// [RFC 5804 section 2.14.1]: https://www.rfc-editor.org/rfc/rfc5804#section-2.14.1
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveUnauthenticateCommand;

impl From<ManagesieveUnauthenticateCommand> for Vec<u8> {
    fn from(_: ManagesieveUnauthenticateCommand) -> Vec<u8> {
        b"UNAUTHENTICATE\r\n".to_vec()
    }
}

/// Failure causes during the ManageSieve UNAUTHENTICATE exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveUnauthenticateError {
    /// The server refused the command, meaning it does not carry the
    /// extension or the session was not authenticated to begin with.
    #[error("ManageSieve UNAUTHENTICATE failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve UNAUTHENTICATE failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve UNAUTHENTICATE coroutine.
pub struct ManagesieveUnauthenticate {
    state: State,
}

impl ManagesieveUnauthenticate {
    /// Creates the coroutine.
    pub fn new() -> Self {
        let send = ManagesieveCommandSend::new(ManagesieveUnauthenticateCommand);
        Self {
            state: State::Send(send),
        }
    }
}

impl Default for ManagesieveUnauthenticate {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveUnauthenticate {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveUnauthenticateError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("session unauthenticated");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveUnauthenticateError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveUnauthenticateCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send unauthenticate"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc5804::unauthenticate::*};

    #[test]
    fn success_returns_ok() {
        let mut unauth = ManagesieveUnauthenticate::new();

        let bytes = expect_wants_write(&mut unauth, None);
        assert_eq!(bytes, b"UNAUTHENTICATE\r\n");

        expect_wants_read(&mut unauth);
        expect_complete_ok(&mut unauth, b"OK\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut unauth = ManagesieveUnauthenticate::new();
        expect_wants_write(&mut unauth, None);
        expect_wants_read(&mut unauth);

        let err = expect_complete_err(&mut unauth, b"NO \"Unknown command\"\r\n");
        let ManagesieveUnauthenticateError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO Unknown command");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut unauth = ManagesieveUnauthenticate::new();
        expect_wants_write(&mut unauth, None);
        expect_wants_read(&mut unauth);

        let err = expect_complete_err(&mut unauth, b"");
        assert!(matches!(
            err,
            ManagesieveUnauthenticateError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveUnauthenticate, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveUnauthenticate) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveUnauthenticate, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveUnauthenticate,
        reply: &[u8],
    ) -> ManagesieveUnauthenticateError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
