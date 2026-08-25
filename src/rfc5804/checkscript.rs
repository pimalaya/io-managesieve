//! The CHECKSCRIPT command, compiling a script without storing it
//! ([RFC 5804 section 2.12]).
//!
//! Everything PUTSCRIPT reports about validity, minus the storage: a NO
//! names the line at fault, an OK may carry WARNINGS, and the server is
//! explicitly forbidden from weighing the script against a quota. The
//! command needs the VERSION capability; a server predating RFC 5804
//! answers NO.
//!
//! [RFC 5804 section 2.12]: https://www.rfc-editor.org/rfc/rfc5804#section-2.12
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
//!     rfc5804::checkscript::ManagesieveScriptCheck,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveScriptCheck::new(b"require [\"fileinto\"];\n");
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
//!         ManagesieveCoroutineState::Complete(Ok(_warnings)) => break,
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
    coroutine::*, managesieve_try, rfc5804::response::ManagesieveCompletion, send::*,
    utils::literal,
};

/// The CHECKSCRIPT command ([RFC 5804 section 2.12]).
///
/// [RFC 5804 section 2.12]: https://www.rfc-editor.org/rfc/rfc5804#section-2.12
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveScriptCheckCommand {
    /// The script source, byte for byte.
    pub script: Vec<u8>,
}

impl From<ManagesieveScriptCheckCommand> for Vec<u8> {
    fn from(cmd: ManagesieveScriptCheckCommand) -> Vec<u8> {
        let mut bytes = b"CHECKSCRIPT ".to_vec();

        bytes.extend(literal(&cmd.script));
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve CHECKSCRIPT exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptCheckError {
    /// The server refused the script, or does not know the command.
    #[error("ManageSieve CHECKSCRIPT failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve CHECKSCRIPT failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve CHECKSCRIPT coroutine.
pub struct ManagesieveScriptCheck {
    state: State,
}

impl ManagesieveScriptCheck {
    /// Builds a CHECKSCRIPT coroutine compiling `script`.
    pub fn new(script: impl AsRef<[u8]>) -> Self {
        let cmd = ManagesieveScriptCheckCommand {
            script: script.as_ref().to_vec(),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveScriptCheck {
    type Yield = ManagesieveYield;
    type Return = Result<Option<String>, ManagesieveScriptCheckError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(response) => {
                        let warnings = response.completion.warnings().map(str::to_string);
                        debug!("script compiles");

                        ManagesieveCoroutineState::Complete(Ok(warnings))
                    }
                    Err(completion) => {
                        let err = ManagesieveScriptCheckError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptCheckCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send checkscript"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    use crate::{coroutine::*, rfc5804::checkscript::*};

    #[test]
    fn success_returns_no_warning() {
        let mut check = ManagesieveScriptCheck::new(b"#comment\n");

        let bytes = expect_wants_write(&mut check, None);
        assert_eq!(bytes, b"CHECKSCRIPT {9+}\r\n#comment\n\r\n");

        expect_wants_read(&mut check);
        assert_eq!(expect_complete_ok(&mut check, b"OK\r\n"), None);
    }

    #[test]
    fn success_with_warnings_returns_their_text() {
        let mut check = ManagesieveScriptCheck::new(b"#comment\n");
        expect_wants_write(&mut check, None);
        expect_wants_read(&mut check);

        let reply = b"OK (WARNINGS) \"line 1: nothing happens\"\r\n";
        assert_eq!(
            expect_complete_ok(&mut check, reply).unwrap(),
            "line 1: nothing happens"
        );
    }

    #[test]
    fn a_syntax_error_returns_rejected_error() {
        let mut check = ManagesieveScriptCheck::new(b"InvalidSieveCommand\n");
        expect_wants_write(&mut check, None);
        expect_wants_read(&mut check);

        let err = expect_complete_err(&mut check, b"NO \"line 2: Syntax error\"\r\n");
        let ManagesieveScriptCheckError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO line 2: Syntax error");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut check = ManagesieveScriptCheck::new(b"");
        expect_wants_write(&mut check, None);
        expect_wants_read(&mut check);

        let err = expect_complete_err(&mut check, b"");
        assert!(matches!(
            err,
            ManagesieveScriptCheckError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptCheck, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptCheck) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptCheck, reply: &[u8]) -> Option<String> {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(warnings)) => warnings,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptCheck,
        reply: &[u8],
    ) -> ManagesieveScriptCheckError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
