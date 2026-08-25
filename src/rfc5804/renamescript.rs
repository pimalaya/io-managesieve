//! The RENAMESCRIPT command, giving a stored script another name ([RFC
//! 5804 section 2.11]).
//!
//! Renaming the active script keeps it active, which is what makes the
//! command worth having: the five-step emulation the specification
//! spells out for servers lacking it (list, get, put, activate, delete)
//! leaves a window where nothing is active. The command needs the
//! VERSION capability; a server predating RFC 5804 answers NO, and a
//! caller that must support one falls back to that sequence itself.
//!
//! [RFC 5804 section 2.11]: https://www.rfc-editor.org/rfc/rfc5804#section-2.11
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
//!     rfc5804::renamescript::ManagesieveScriptRename,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveScriptRename::new("foo", "bar");
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

/// The RENAMESCRIPT command ([RFC 5804 section 2.11]).
///
/// [RFC 5804 section 2.11]: https://www.rfc-editor.org/rfc/rfc5804#section-2.11
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveScriptRenameCommand {
    /// The name the script has now.
    pub name: String,
    /// The name it should have.
    pub new_name: String,
}

impl From<ManagesieveScriptRenameCommand> for Vec<u8> {
    fn from(cmd: ManagesieveScriptRenameCommand) -> Vec<u8> {
        let mut bytes = b"RENAMESCRIPT ".to_vec();

        bytes.extend(string(cmd.name.as_bytes()));
        bytes.push(b' ');
        bytes.extend(string(cmd.new_name.as_bytes()));
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve RENAMESCRIPT exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptRenameError {
    /// The server refused the rename, NONEXISTENT and ALREADYEXISTS
    /// being the codes to expect, and a plain NO meaning the server
    /// does not know the command.
    #[error("ManageSieve RENAMESCRIPT failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve RENAMESCRIPT failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve RENAMESCRIPT coroutine.
pub struct ManagesieveScriptRename {
    state: State,
}

impl ManagesieveScriptRename {
    /// Builds a RENAMESCRIPT coroutine renaming `name` to `new_name`.
    pub fn new(name: impl AsRef<str>, new_name: impl AsRef<str>) -> Self {
        let cmd = ManagesieveScriptRenameCommand {
            name: name.as_ref().to_string(),
            new_name: new_name.as_ref().to_string(),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveScriptRename {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveScriptRenameError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("script renamed");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveScriptRenameError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptRenameCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send renamescript"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc5804::renamescript::*};

    #[test]
    fn success_returns_ok() {
        let mut rename = ManagesieveScriptRename::new("foo", "bar");

        let bytes = expect_wants_write(&mut rename, None);
        assert_eq!(bytes, b"RENAMESCRIPT \"foo\" \"bar\"\r\n");

        expect_wants_read(&mut rename);
        expect_complete_ok(&mut rename, b"OK\r\n");
    }

    #[test]
    fn a_taken_name_returns_rejected_error() {
        let mut rename = ManagesieveScriptRename::new("baz", "bar");
        expect_wants_write(&mut rename, None);
        expect_wants_read(&mut rename);

        let err = expect_complete_err(&mut rename, b"NO \"bar already exists\"\r\n");
        let ManagesieveScriptRenameError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO bar already exists");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut rename = ManagesieveScriptRename::new("foo", "bar");
        expect_wants_write(&mut rename, None);
        expect_wants_read(&mut rename);

        let err = expect_complete_err(&mut rename, b"");
        assert!(matches!(
            err,
            ManagesieveScriptRenameError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptRename, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptRename) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptRename, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptRename,
        reply: &[u8],
    ) -> ManagesieveScriptRenameError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
