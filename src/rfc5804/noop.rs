//! The NOOP command, a round trip that does nothing else ([RFC 5804
//! section 2.13]).
//!
//! Two uses: resetting the server's inactivity timer, and
//! resynchronising after a STARTTLS upgrade. The optional tag is what
//! makes the second one work, since the server echoes it back in the
//! TAG response code and a client can tell its own round trip from a
//! reply it did not ask for. The command needs the VERSION capability;
//! a server predating RFC 5804 answers NO.
//!
//! [RFC 5804 section 2.13]: https://www.rfc-editor.org/rfc/rfc5804#section-2.13
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
//!     rfc5804::noop::ManagesieveNoop,
//! };
//!
//! // Ready stream needed (TCP-connected, greeting read)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveNoop::new(Some("STARTTLS-SYNC-42"));
//! let mut arg = None;
//!
//! let tag = loop {
//!     match coroutine.resume(arg.take()) {
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ManagesieveCoroutineState::Complete(Ok(tag)) => break tag,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! assert_eq!(tag.as_deref(), Some("STARTTLS-SYNC-42"));
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
    rfc5804::response::{ManagesieveCompletion, ManagesieveResponseCode},
    send::*,
    utils::string,
};

/// The NOOP command ([RFC 5804 section 2.13]).
///
/// [RFC 5804 section 2.13]: https://www.rfc-editor.org/rfc/rfc5804#section-2.13
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveNoopCommand {
    /// The string the server echoes back in the TAG response code.
    ///
    /// A server sends no TAG at all when the command carries none.
    pub tag: Option<String>,
}

impl From<ManagesieveNoopCommand> for Vec<u8> {
    fn from(cmd: ManagesieveNoopCommand) -> Vec<u8> {
        let mut bytes = b"NOOP".to_vec();

        if let Some(tag) = cmd.tag {
            bytes.push(b' ');
            bytes.extend(string(tag.as_bytes()));
        }

        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Failure causes during the ManageSieve NOOP exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveNoopError {
    /// The server refused the command, which for a NOOP means it does
    /// not know it.
    #[error("ManageSieve NOOP failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve NOOP failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve NOOP coroutine.
pub struct ManagesieveNoop {
    state: State,
}

impl ManagesieveNoop {
    /// Builds a NOOP coroutine, optionally asking the server to echo
    /// `tag` back.
    pub fn new(tag: Option<impl AsRef<str>>) -> Self {
        let cmd = ManagesieveNoopCommand {
            tag: tag.map(|tag| tag.as_ref().to_string()),
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveNoop {
    type Yield = ManagesieveYield;
    type Return = Result<Option<String>, ManagesieveNoopError>;

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
                        let err = ManagesieveNoopError::Rejected(completion);
                        return ManagesieveCoroutineState::Complete(Err(err));
                    }
                };

                let tag = match response.completion.code {
                    Some(ManagesieveResponseCode::Tag(tag)) => Some(tag),
                    _ => None,
                };

                debug!("noop accepted");

                ManagesieveCoroutineState::Complete(Ok(tag))
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveNoopCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send noop"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    use crate::{coroutine::*, rfc5804::noop::*};

    #[test]
    fn success_returns_no_tag() {
        let mut noop = ManagesieveNoop::new(None::<&str>);

        let bytes = expect_wants_write(&mut noop, None);
        assert_eq!(bytes, b"NOOP\r\n");

        expect_wants_read(&mut noop);
        assert_eq!(
            expect_complete_ok(&mut noop, b"OK \"NOOP completed\"\r\n"),
            None
        );
    }

    #[test]
    fn a_tagged_noop_returns_the_tag_the_server_echoed() {
        let mut noop = ManagesieveNoop::new(Some("STARTTLS-SYNC-42"));

        let bytes = expect_wants_write(&mut noop, None);
        assert_eq!(bytes, b"NOOP \"STARTTLS-SYNC-42\"\r\n");

        expect_wants_read(&mut noop);

        let reply = b"OK (TAG {16}\r\nSTARTTLS-SYNC-42) \"Done\"\r\n";
        assert_eq!(
            expect_complete_ok(&mut noop, reply).unwrap(),
            "STARTTLS-SYNC-42"
        );
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut noop = ManagesieveNoop::new(None::<&str>);
        expect_wants_write(&mut noop, None);
        expect_wants_read(&mut noop);

        let err = expect_complete_err(&mut noop, b"NO \"Unknown command\"\r\n");
        let ManagesieveNoopError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO Unknown command");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut noop = ManagesieveNoop::new(None::<&str>);
        expect_wants_write(&mut noop, None);
        expect_wants_read(&mut noop);

        let err = expect_complete_err(&mut noop, b"");
        assert!(matches!(
            err,
            ManagesieveNoopError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveNoop, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveNoop) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveNoop, reply: &[u8]) -> Option<String> {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(tag)) => tag,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut ManagesieveNoop, reply: &[u8]) -> ManagesieveNoopError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
