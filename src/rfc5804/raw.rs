//! A passthrough for commands this crate does not model.
//!
//! What goes out is what the caller wrote, and what comes back is the
//! parsed response rather than an interpretation of it: no status is
//! turned into an error, so a NO reaches the caller as a NO. The
//! framing is still read properly, literals included, which is the part
//! a caller cannot reasonably redo by hand.
//!
//! The command travels as one write, so a command carrying a literal is
//! passed whole, marker and octets together, and the CRLF closing it is
//! added when the caller left it out. Nothing here checks the grammar:
//! a malformed command desynchronises the session exactly as it would
//! against a telnet client.
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
//!     rfc5804::raw::ManagesieveRaw,
//! };
//!
//! // Ready stream needed (TCP-connected, greeting read)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveRaw::new("LISTSCRIPTS");
//! let mut arg = None;
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(response)) => break response,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{}", response.completion);
//! ```

use core::fmt;

use alloc::vec::Vec;

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, managesieve_try, rfc5804::response::ManagesieveResponse, send::*};

/// An arbitrary command line, CRLF added when it is missing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveRawCommand {
    /// The command bytes, without their terminating CRLF.
    pub command: Vec<u8>,
}

impl From<ManagesieveRawCommand> for Vec<u8> {
    fn from(cmd: ManagesieveRawCommand) -> Vec<u8> {
        let mut bytes = cmd.command;

        if !bytes.ends_with(b"\r\n") {
            bytes.extend_from_slice(b"\r\n");
        }

        bytes
    }
}

/// Failure causes during a raw ManageSieve exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveRawError {
    /// The underlying command exchange failed.
    ///
    /// There is no rejection variant: a NO or BYE is part of what the
    /// caller asked to see, so it travels in the response rather than
    /// in an error.
    #[error("ManageSieve raw command failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve raw passthrough coroutine.
pub struct ManagesieveRaw {
    state: State,
}

impl ManagesieveRaw {
    /// Builds a raw coroutine sending `command`.
    pub fn new(command: impl Into<Vec<u8>>) -> Self {
        let cmd = ManagesieveRawCommand {
            command: command.into(),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveRaw {
    type Yield = ManagesieveYield;
    type Return = Result<ManagesieveResponse, ManagesieveRawError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);
                debug!("raw response read");

                ManagesieveCoroutineState::Complete(Ok(out.response))
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveRawCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send raw command"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{
        coroutine::*,
        rfc5804::{raw::*, response::ManagesieveStatus},
    };

    #[test]
    fn adds_the_crlf_the_caller_left_out() {
        let mut raw = ManagesieveRaw::new("LISTSCRIPTS");

        let bytes = expect_wants_write(&mut raw, None);
        assert_eq!(bytes, b"LISTSCRIPTS\r\n");
    }

    #[test]
    fn keeps_the_crlf_the_caller_wrote() {
        let mut raw = ManagesieveRaw::new(b"CAPABILITY\r\n".to_vec());

        let bytes = expect_wants_write(&mut raw, None);
        assert_eq!(bytes, b"CAPABILITY\r\n");
    }

    #[test]
    fn a_rejection_reaches_the_caller_as_a_response() {
        let mut raw = ManagesieveRaw::new("DELETESCRIPT \"baz\"");
        expect_wants_write(&mut raw, None);
        expect_wants_read(&mut raw);

        let response = match raw.resume(Some(b"NO (ACTIVE) \"nope\"\r\n")) {
            ManagesieveCoroutineState::Complete(Ok(response)) => response,
            state => panic!("expected Complete(Ok), got {state:?}"),
        };

        assert_eq!(response.completion.status, ManagesieveStatus::No);
        assert_eq!(response.completion.to_string(), "NO (ACTIVE) nope");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut raw = ManagesieveRaw::new("CAPABILITY");
        expect_wants_write(&mut raw, None);
        expect_wants_read(&mut raw);

        let err = match raw.resume(Some(b"")) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        };

        assert!(matches!(
            err,
            ManagesieveRawError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveRaw, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveRaw) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }
}
