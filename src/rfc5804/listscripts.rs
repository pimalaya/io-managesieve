//! The LISTSCRIPTS command, naming the scripts a user has stored ([RFC
//! 5804 section 2.7]).
//!
//! One data line per script, each a name and, on at most one of them,
//! the ACTIVE atom marking the script the server actually runs. A user
//! with no active script gets no marker at all, which is a state of its
//! own rather than an error: Sieve filtering is simply off.
//!
//! [RFC 5804 section 2.7]: https://www.rfc-editor.org/rfc/rfc5804#section-2.7
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
//!     rfc5804::listscripts::ManagesieveScriptList,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveScriptList::new();
//! let mut arg = None;
//!
//! let scripts = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(scripts)) => break scripts,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{scripts:?}");
//! ```

use core::fmt;

use alloc::{string::String, vec::Vec};

use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*,
    managesieve_try,
    rfc5804::response::{ManagesieveCompletion, ManagesieveDataLine},
    send::*,
};

/// One stored script, by name and by whether it is the active one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveScript {
    /// The script name, decoded from the UTF-8 the specification asks
    /// for, with invalid sequences replaced.
    pub name: String,
    /// Whether this is the script the server runs on incoming mail.
    pub active: bool,
}

impl ManagesieveScript {
    /// Reads a script out of one LISTSCRIPTS data line.
    fn parse(line: &ManagesieveDataLine) -> Option<Self> {
        let name = String::from_utf8_lossy(line.string(0)?).into_owned();
        let active = line.has_atom("ACTIVE");

        Some(Self { name, active })
    }
}

impl fmt::Display for ManagesieveScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.active {
            true => write!(f, "{} (active)", self.name),
            false => f.write_str(&self.name),
        }
    }
}

/// The LISTSCRIPTS command ([RFC 5804 section 2.7]).
///
/// [RFC 5804 section 2.7]: https://www.rfc-editor.org/rfc/rfc5804#section-2.7
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveScriptListCommand;

impl From<ManagesieveScriptListCommand> for Vec<u8> {
    fn from(_: ManagesieveScriptListCommand) -> Vec<u8> {
        b"LISTSCRIPTS\r\n".to_vec()
    }
}

/// Failure causes during the ManageSieve LISTSCRIPTS exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveScriptListError {
    /// The server refused the command.
    #[error("ManageSieve LISTSCRIPTS failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve LISTSCRIPTS failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve LISTSCRIPTS coroutine.
pub struct ManagesieveScriptList {
    state: State,
}

impl ManagesieveScriptList {
    /// Creates the coroutine.
    pub fn new() -> Self {
        let send = ManagesieveCommandSend::new(ManagesieveScriptListCommand);
        Self {
            state: State::Send(send),
        }
    }
}

impl Default for ManagesieveScriptList {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveScriptList {
    type Yield = ManagesieveYield;
    type Return = Result<Vec<ManagesieveScript>, ManagesieveScriptListError>;

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
                        let err = ManagesieveScriptListError::Rejected(completion);
                        return ManagesieveCoroutineState::Complete(Err(err));
                    }
                };

                let scripts: Vec<_> = response
                    .data
                    .iter()
                    .filter_map(ManagesieveScript::parse)
                    .collect();
                debug!("listed {} scripts", scripts.len());

                ManagesieveCoroutineState::Complete(Ok(scripts))
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveScriptListCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send listscripts"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc5804::listscripts::*};

    #[test]
    fn success_returns_the_scripts_and_marks_the_active_one() {
        let mut list = ManagesieveScriptList::new();

        let bytes = expect_wants_write(&mut list, None);
        assert_eq!(bytes, b"LISTSCRIPTS\r\n");

        expect_wants_read(&mut list);

        let reply = b"\"summer_script\"\r\n{13}\r\nclever\"script\r\n\"main\" active\r\nOK\r\n";
        let scripts = expect_complete_ok(&mut list, reply);

        assert_eq!(scripts.len(), 3);
        assert_eq!(scripts[0].to_string(), "summer_script");
        assert_eq!(scripts[1].name, "clever\"script");
        assert!(!scripts[1].active);
        assert_eq!(scripts[2].to_string(), "main (active)");
    }

    #[test]
    fn no_script_returns_an_empty_list() {
        let mut list = ManagesieveScriptList::new();
        expect_wants_write(&mut list, None);
        expect_wants_read(&mut list);

        assert!(expect_complete_ok(&mut list, b"OK\r\n").is_empty());
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut list = ManagesieveScriptList::new();
        expect_wants_write(&mut list, None);
        expect_wants_read(&mut list);

        let err = expect_complete_err(&mut list, b"NO \"Authenticate first\"\r\n");
        let ManagesieveScriptListError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO Authenticate first");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut list = ManagesieveScriptList::new();
        expect_wants_write(&mut list, None);
        expect_wants_read(&mut list);

        let err = expect_complete_err(&mut list, b"");
        assert!(matches!(
            err,
            ManagesieveScriptListError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveScriptList, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveScriptList) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveScriptList, reply: &[u8]) -> Vec<ManagesieveScript> {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(scripts)) => scripts,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveScriptList,
        reply: &[u8],
    ) -> ManagesieveScriptListError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
