//! The SETACTIVE command, choosing which script filters incoming mail
//! ([RFC 5804 section 2.8]).
//!
//! A user has zero or one active script, so activating one deactivates
//! whichever was active before. The empty name is the wire form of
//! turning Sieve off, which the coroutine takes as [`None`] rather than
//! as an empty string, and doing it twice is not an error.
//!
//! [RFC 5804 section 2.8]: https://www.rfc-editor.org/rfc/rfc5804#section-2.8
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
//!     rfc5804::setactive::ManagesieveScriptActivate,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveScriptActivate::new(Some("vacation"));
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

/// The SETACTIVE command ([RFC 5804 section 2.8]).
///
/// [RFC 5804 section 2.8]: https://www.rfc-editor.org/rfc/rfc5804#section-2.8
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveScriptActivateCommand {
    /// The script to activate, or [`None`] to deactivate whichever is
    /// active, which travels as the empty name.
    pub name: Option<String>,
}

impl From<ManagesieveScriptActivateCommand> for Vec<u8> {
    fn from(cmd: ManagesieveScriptActivateCommand) -> Vec<u8> {
        let mut bytes = b"SETACTIVE ".to_vec();

        bytes.extend(string(cmd.name.unwrap_or_default().as_bytes()));
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve SETACTIVE exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptActivateError {
    /// The server refused the change, NONEXISTENT being the code to
    /// expect for a name that is not there.
    #[error("ManageSieve SETACTIVE failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve SETACTIVE failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve SETACTIVE coroutine.
pub struct ManagesieveScriptActivate {
    state: State,
}

impl ManagesieveScriptActivate {
    /// Builds a SETACTIVE coroutine activating `name`, or deactivating
    /// whichever script is active when given [`None`].
    pub fn new(name: Option<impl AsRef<str>>) -> Self {
        let cmd = ManagesieveScriptActivateCommand {
            name: name.map(|name| name.as_ref().to_string()),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveScriptActivate {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveScriptActivateError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("active script set");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveScriptActivateError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptActivateCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send setactive"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        coroutine::*,
        rfc5804::{response::ManagesieveResponseCode, setactive::*},
    };

    #[test]
    fn success_returns_ok() {
        let mut activate = ManagesieveScriptActivate::new(Some("vacationscript"));

        let bytes = expect_wants_write(&mut activate, None);
        assert_eq!(bytes, b"SETACTIVE \"vacationscript\"\r\n");

        expect_wants_read(&mut activate);
        expect_complete_ok(&mut activate, b"OK\r\n");
    }

    #[test]
    fn no_name_deactivates_through_the_empty_name() {
        let mut activate = ManagesieveScriptActivate::new(None::<&str>);

        let bytes = expect_wants_write(&mut activate, None);
        assert_eq!(bytes, b"SETACTIVE \"\"\r\n");

        expect_wants_read(&mut activate);
        expect_complete_ok(&mut activate, b"OK\r\n");
    }

    #[test]
    fn an_unknown_name_returns_rejected_error() {
        let mut activate = ManagesieveScriptActivate::new(Some("baz"));
        expect_wants_write(&mut activate, None);
        expect_wants_read(&mut activate);

        let reply = b"NO (NONEXISTENT) \"There is no script by that name\"\r\n";
        let err = expect_complete_err(&mut activate, reply);
        let ManagesieveScriptActivateError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.code, Some(ManagesieveResponseCode::Nonexistent));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut activate = ManagesieveScriptActivate::new(Some("main"));
        expect_wants_write(&mut activate, None);
        expect_wants_read(&mut activate);

        let err = expect_complete_err(&mut activate, b"");
        assert!(matches!(
            err,
            ManagesieveScriptActivateError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptActivate, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptActivate) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptActivate, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptActivate,
        reply: &[u8],
    ) -> ManagesieveScriptActivateError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
