//! The PUTSCRIPT command, uploading one script ([RFC 5804 section
//! 2.6]).
//!
//! The server compiles what it is given, so a NO here is a Sieve
//! syntax error rather than a transport failure, and its text names the
//! line at fault. An OK may still carry the WARNINGS code, which is a
//! script that compiled and is probably not what its author meant; the
//! coroutine returns that text so a caller can show it.
//!
//! Uploading replaces a script of the same name, and replacing the
//! active script changes what runs on incoming mail without any
//! SETACTIVE. Quotas are the server's, so a large script is worth a
//! [`crate::rfc5804::havespace`] first.
//!
//! [RFC 5804 section 2.6]: https://www.rfc-editor.org/rfc/rfc5804#section-2.6
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
//!     rfc5804::putscript::ManagesieveScriptPut,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let script = b"require [\"fileinto\"];\n";
//! let mut coroutine = ManagesieveScriptPut::new("main", script);
//! let mut arg = None;
//!
//! let warnings = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(warnings)) => break warnings,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! if let Some(warnings) = warnings {
//!     println!("{warnings}");
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
    coroutine::*,
    managesieve_try,
    rfc5804::response::ManagesieveCompletion,
    send::*,
    utils::{literal, string},
};

/// The PUTSCRIPT command ([RFC 5804 section 2.6]).
///
/// [RFC 5804 section 2.6]: https://www.rfc-editor.org/rfc/rfc5804#section-2.6
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveScriptPutCommand {
    /// The name to store the script under.
    pub name: String,
    /// The script source, byte for byte.
    pub script: Vec<u8>,
}

impl From<ManagesieveScriptPutCommand> for Vec<u8> {
    fn from(cmd: ManagesieveScriptPutCommand) -> Vec<u8> {
        let mut bytes = b"PUTSCRIPT ".to_vec();

        bytes.extend(string(cmd.name.as_bytes()));
        bytes.push(b' ');
        bytes.extend(literal(&cmd.script));
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve PUTSCRIPT exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptPutError {
    /// The server refused the script, whether for a syntax error or a
    /// quota.
    #[error("ManageSieve PUTSCRIPT failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve PUTSCRIPT failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve PUTSCRIPT coroutine.
pub struct ManagesieveScriptPut {
    state: State,
}

impl ManagesieveScriptPut {
    /// Builds a PUTSCRIPT coroutine storing `script` under `name`.
    pub fn new(name: impl AsRef<str>, script: impl AsRef<[u8]>) -> Self {
        let cmd = ManagesieveScriptPutCommand {
            name: name.as_ref().to_string(),
            script: script.as_ref().to_vec(),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveScriptPut {
    type Yield = ManagesieveYield;
    type Return = Result<Option<String>, ManagesieveScriptPutError>;

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
                        debug!("script stored");

                        ManagesieveCoroutineState::Complete(Ok(warnings))
                    }
                    Err(completion) => {
                        let err = ManagesieveScriptPutError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptPutCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send putscript"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    use crate::{coroutine::*, rfc5804::putscript::*};

    #[test]
    fn success_returns_no_warning() {
        let mut put = ManagesieveScriptPut::new("main", b"require [\"fileinto\"];\n");

        let bytes = expect_wants_write(&mut put, None);
        assert_eq!(
            bytes,
            b"PUTSCRIPT \"main\" {22+}\r\nrequire [\"fileinto\"];\n\r\n"
        );

        expect_wants_read(&mut put);
        assert_eq!(expect_complete_ok(&mut put, b"OK\r\n"), None);
    }

    #[test]
    fn success_with_warnings_returns_their_text() {
        let mut put = ManagesieveScriptPut::new("main", b"redirect \"a@b\";\n");
        expect_wants_write(&mut put, None);
        expect_wants_read(&mut put);

        let reply = b"OK (WARNINGS) \"line 8: redirect limit is 2\"\r\n";
        let warnings = expect_complete_ok(&mut put, reply);

        assert_eq!(warnings.unwrap(), "line 8: redirect limit is 2");
    }

    #[test]
    fn a_syntax_error_returns_rejected_error() {
        let mut put = ManagesieveScriptPut::new("foo", b"InvalidSieveCommand\n");
        expect_wants_write(&mut put, None);
        expect_wants_read(&mut put);

        let err = expect_complete_err(&mut put, b"NO \"line 2: Syntax error\"\r\n");
        let ManagesieveScriptPutError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO line 2: Syntax error");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut put = ManagesieveScriptPut::new("main", b"");
        expect_wants_write(&mut put, None);
        expect_wants_read(&mut put);

        let err = expect_complete_err(&mut put, b"");
        assert!(matches!(
            err,
            ManagesieveScriptPutError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptPut, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptPut) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptPut, reply: &[u8]) -> Option<String> {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(warnings)) => warnings,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptPut,
        reply: &[u8],
    ) -> ManagesieveScriptPutError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
