//! The DELETESCRIPT command, removing one stored script ([RFC 5804
//! section 2.10]).
//!
//! A server refuses to delete the active script, answering NO with the
//! ACTIVE code, so removing the script that filters incoming mail takes
//! a [`crate::rfc5804::setactive`] with no name first. A name that is
//! not there answers NO with NONEXISTENT.
//!
//! [RFC 5804 section 2.10]: https://www.rfc-editor.org/rfc/rfc5804#section-2.10
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
//!     rfc5804::deletescript::ManagesieveScriptDelete,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveScriptDelete::new("summer");
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

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*, managesieve_try, rfc5804::response::ManagesieveCompletion, send::*, utils::string,
};

/// The DELETESCRIPT command ([RFC 5804 section 2.10]).
///
/// [RFC 5804 section 2.10]: https://www.rfc-editor.org/rfc/rfc5804#section-2.10
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveScriptDeleteCommand {
    /// The name of the script to remove.
    pub name: String,
}

impl From<ManagesieveScriptDeleteCommand> for Vec<u8> {
    fn from(cmd: ManagesieveScriptDeleteCommand) -> Vec<u8> {
        let mut bytes = b"DELETESCRIPT ".to_vec();

        bytes.extend(string(cmd.name.as_bytes()));
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve DELETESCRIPT exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptDeleteError {
    /// The server refused the deletion, ACTIVE and NONEXISTENT being
    /// the codes to expect.
    #[error("ManageSieve DELETESCRIPT failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve DELETESCRIPT failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve DELETESCRIPT coroutine.
pub struct ManagesieveScriptDelete {
    state: State,
}

impl ManagesieveScriptDelete {
    /// Builds a DELETESCRIPT coroutine removing the script called
    /// `name`.
    pub fn new(name: impl AsRef<str>) -> Self {
        let cmd = ManagesieveScriptDeleteCommand {
            name: name.as_ref().to_string(),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveScriptDelete {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveScriptDeleteError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("script deleted");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveScriptDeleteError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptDeleteCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send deletescript"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        coroutine::*,
        rfc5804::{deletescript::*, response::ManagesieveResponseCode},
    };

    #[test]
    fn success_returns_ok() {
        let mut delete = ManagesieveScriptDelete::new("foo");

        let bytes = expect_wants_write(&mut delete, None);
        assert_eq!(bytes, b"DELETESCRIPT \"foo\"\r\n");

        expect_wants_read(&mut delete);
        expect_complete_ok(&mut delete, b"OK\r\n");
    }

    #[test]
    fn deleting_the_active_script_returns_rejected_error() {
        let mut delete = ManagesieveScriptDelete::new("baz");
        expect_wants_write(&mut delete, None);
        expect_wants_read(&mut delete);

        let reply = b"NO (ACTIVE) \"You may not delete an active script\"\r\n";
        let err = expect_complete_err(&mut delete, reply);
        let ManagesieveScriptDeleteError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.code, Some(ManagesieveResponseCode::Active));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut delete = ManagesieveScriptDelete::new("foo");
        expect_wants_write(&mut delete, None);
        expect_wants_read(&mut delete);

        let err = expect_complete_err(&mut delete, b"");
        assert!(matches!(
            err,
            ManagesieveScriptDeleteError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptDelete, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptDelete) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptDelete, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptDelete,
        reply: &[u8],
    ) -> ManagesieveScriptDeleteError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
