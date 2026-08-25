//! The LOGOUT command, ending a session cleanly ([RFC 5804 section
//! 2.3]).
//!
//! The server answers OK and closes. Waiting for that OK before closing
//! the socket is what keeps the connection out of the server's TIME_WAIT
//! state, so the coroutine reads it rather than writing and walking
//! away.
//!
//! [RFC 5804 section 2.3]: https://www.rfc-editor.org/rfc/rfc5804#section-2.3
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
//!     rfc5804::logout::ManagesieveLogout,
//! };
//!
//! // Ready stream needed (TCP-connected, greeting read)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveLogout::new();
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

/// The LOGOUT command ([RFC 5804 section 2.3]).
///
/// [RFC 5804 section 2.3]: https://www.rfc-editor.org/rfc/rfc5804#section-2.3
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveLogoutCommand;

impl From<ManagesieveLogoutCommand> for Vec<u8> {
    fn from(_: ManagesieveLogoutCommand) -> Vec<u8> {
        b"LOGOUT\r\n".to_vec()
    }
}

/// Failure causes during the ManageSieve LOGOUT exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveLogoutError {
    /// The server answered something other than OK, which the
    /// specification says it must not.
    #[error("ManageSieve LOGOUT failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve LOGOUT failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve LOGOUT coroutine.
pub struct ManagesieveLogout {
    state: State,
}

impl ManagesieveLogout {
    /// Creates the coroutine.
    pub fn new() -> Self {
        let send = ManagesieveCommandSend::new(ManagesieveLogoutCommand);
        Self {
            state: State::Send(send),
        }
    }
}

impl Default for ManagesieveLogout {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveLogout {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveLogoutError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("session closed");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveLogoutError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveLogoutCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send logout"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc5804::logout::*};

    #[test]
    fn success_returns_ok() {
        let mut logout = ManagesieveLogout::new();

        let bytes = expect_wants_write(&mut logout, None);
        assert_eq!(bytes, b"LOGOUT\r\n");

        expect_wants_read(&mut logout);
        expect_complete_ok(&mut logout, b"OK\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut logout = ManagesieveLogout::new();
        expect_wants_write(&mut logout, None);
        expect_wants_read(&mut logout);

        let err = expect_complete_err(&mut logout, b"NO \"what\"\r\n");
        let ManagesieveLogoutError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO what");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut logout = ManagesieveLogout::new();
        expect_wants_write(&mut logout, None);
        expect_wants_read(&mut logout);

        let err = expect_complete_err(&mut logout, b"");
        assert!(matches!(
            err,
            ManagesieveLogoutError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveLogout, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveLogout) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveLogout, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut ManagesieveLogout, reply: &[u8]) -> ManagesieveLogoutError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
