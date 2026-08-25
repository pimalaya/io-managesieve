//! The GETSCRIPT command, downloading one stored script ([RFC 5804
//! section 2.9]).
//!
//! The script comes back as a single string, which a server of any size
//! sends as a literal, so the bytes reach the caller exactly as they
//! were stored. They stay bytes here: the specification puts a Sieve
//! script in UTF-8, and decoding it is the caller's decision rather
//! than a failure this coroutine can usefully raise.
//!
//! [RFC 5804 section 2.9]: https://www.rfc-editor.org/rfc/rfc5804#section-2.9
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
//!     rfc5804::getscript::ManagesieveScriptGet,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveScriptGet::new("vacation");
//! let mut arg = None;
//!
//! let script = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(script)) => break script,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{}", String::from_utf8_lossy(&script));
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

/// The GETSCRIPT command ([RFC 5804 section 2.9]).
///
/// [RFC 5804 section 2.9]: https://www.rfc-editor.org/rfc/rfc5804#section-2.9
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveScriptGetCommand {
    /// The name of the script to download.
    pub name: String,
}

impl From<ManagesieveScriptGetCommand> for Vec<u8> {
    fn from(cmd: ManagesieveScriptGetCommand) -> Vec<u8> {
        let mut bytes = b"GETSCRIPT ".to_vec();

        bytes.extend(string(cmd.name.as_bytes()));
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve GETSCRIPT exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptGetError {
    /// The server refused the command, NONEXISTENT being the code to
    /// expect for a name that is not there.
    #[error("ManageSieve GETSCRIPT failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The server answered OK without sending the script.
    #[error("ManageSieve GETSCRIPT failed: server returned no script")]
    MissingScript,
    /// The underlying command exchange failed.
    #[error("ManageSieve GETSCRIPT failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve GETSCRIPT coroutine.
pub struct ManagesieveScriptGet {
    state: State,
}

impl ManagesieveScriptGet {
    /// Builds a GETSCRIPT coroutine downloading the script called
    /// `name`.
    pub fn new(name: impl AsRef<str>) -> Self {
        let cmd = ManagesieveScriptGetCommand {
            name: name.as_ref().to_string(),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveScriptGet {
    type Yield = ManagesieveYield;
    type Return = Result<Vec<u8>, ManagesieveScriptGetError>;

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
                        let err = ManagesieveScriptGetError::Rejected(completion);
                        return ManagesieveCoroutineState::Complete(Err(err));
                    }
                };

                let script = response.data.first().and_then(|line| line.string(0));

                let Some(script) = script else {
                    let err = ManagesieveScriptGetError::MissingScript;
                    return ManagesieveCoroutineState::Complete(Err(err));
                };

                debug!("downloaded {} bytes of script", script.len());

                ManagesieveCoroutineState::Complete(Ok(script.to_vec()))
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptGetCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send getscript"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        coroutine::*,
        rfc5804::{getscript::*, response::ManagesieveResponseCode},
    };

    #[test]
    fn success_returns_the_script_bytes() {
        let mut get = ManagesieveScriptGet::new("myscript");

        let bytes = expect_wants_write(&mut get, None);
        assert_eq!(bytes, b"GETSCRIPT \"myscript\"\r\n");

        expect_wants_read(&mut get);

        let reply =
            b"{54}\r\n#this is my wonderful script\r\nreject \"I reject all\";\r\n\r\nOK\r\n";
        let script = expect_complete_ok(&mut get, reply);

        assert_eq!(
            script,
            b"#this is my wonderful script\r\nreject \"I reject all\";\r\n"
        );
    }

    #[test]
    fn quotes_a_name_that_needs_a_literal() {
        let mut get = ManagesieveScriptGet::new("two\nlines");

        let bytes = expect_wants_write(&mut get, None);
        assert_eq!(bytes, b"GETSCRIPT {9+}\r\ntwo\nlines\r\n");
    }

    #[test]
    fn missing_script_returns_missing_script_error() {
        let mut get = ManagesieveScriptGet::new("myscript");
        expect_wants_write(&mut get, None);
        expect_wants_read(&mut get);

        let err = expect_complete_err(&mut get, b"OK\r\n");
        assert_eq!(err, ManagesieveScriptGetError::MissingScript);
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut get = ManagesieveScriptGet::new("baz");
        expect_wants_write(&mut get, None);
        expect_wants_read(&mut get);

        let reply = b"NO (NONEXISTENT) \"There is no script by that name\"\r\n";
        let err = expect_complete_err(&mut get, reply);
        let ManagesieveScriptGetError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.code, Some(ManagesieveResponseCode::Nonexistent));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut get = ManagesieveScriptGet::new("myscript");
        expect_wants_write(&mut get, None);
        expect_wants_read(&mut get);

        let err = expect_complete_err(&mut get, b"");
        assert!(matches!(
            err,
            ManagesieveScriptGetError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptGet, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptGet) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptGet, reply: &[u8]) -> Vec<u8> {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(script)) => script,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptGet,
        reply: &[u8],
    ) -> ManagesieveScriptGetError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
