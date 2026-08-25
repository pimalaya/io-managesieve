//! The HAVESPACE command, asking whether a script would fit ([RFC 5804
//! section 2.5]).
//!
//! Both the name and the size travel, since a server weighs a
//! replacement differently from a new script. The answer is advisory:
//! disk conditions change between the question and the upload, so
//! PUTSCRIPT may still come back with a QUOTA code.
//!
//! A NO is the honest answer to the question rather than a transport
//! failure, and it reaches the caller as
//! [`ManagesieveHaveSpaceError::Rejected`] carrying the QUOTA code
//! naming which limit was hit.
//!
//! [RFC 5804 section 2.5]: https://www.rfc-editor.org/rfc/rfc5804#section-2.5
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
//!     rfc5804::havespace::ManagesieveHaveSpace,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, authenticated)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveHaveSpace::new("myscript", 435);
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
    format,
    string::{String, ToString},
    vec::Vec,
};

use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*, managesieve_try, rfc5804::response::ManagesieveCompletion, send::*, utils::string,
};

/// The HAVESPACE command ([RFC 5804 section 2.5]).
///
/// [RFC 5804 section 2.5]: https://www.rfc-editor.org/rfc/rfc5804#section-2.5
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveHaveSpaceCommand {
    /// The name the script would be stored under.
    pub name: String,
    /// The size of the script in octets.
    pub size: u32,
}

impl From<ManagesieveHaveSpaceCommand> for Vec<u8> {
    fn from(cmd: ManagesieveHaveSpaceCommand) -> Vec<u8> {
        let mut bytes = b"HAVESPACE ".to_vec();

        bytes.extend(string(cmd.name.as_bytes()));
        bytes.extend_from_slice(format!(" {}\r\n", cmd.size).as_bytes());
        bytes
    }
}

/// Failure causes during the ManageSieve HAVESPACE exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveHaveSpaceError {
    /// The script would not fit, or the server refused the question.
    #[error("ManageSieve HAVESPACE failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The underlying command exchange failed.
    #[error("ManageSieve HAVESPACE failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve HAVESPACE coroutine.
pub struct ManagesieveHaveSpace {
    state: State,
}

impl ManagesieveHaveSpace {
    /// Builds a HAVESPACE coroutine asking whether `size` octets fit
    /// under `name`.
    pub fn new(name: impl AsRef<str>, size: u32) -> Self {
        let cmd = ManagesieveHaveSpaceCommand {
            name: name.as_ref().to_string(),
            size,
        };

        Self {
            state: State::Send(ManagesieveCommandSend::new(cmd)),
        }
    }
}

impl ManagesieveCoroutine for ManagesieveHaveSpace {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveHaveSpaceError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("space available");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveHaveSpaceError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveHaveSpaceCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send havespace"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        coroutine::*,
        rfc5804::{
            havespace::*,
            response::{ManagesieveQuota, ManagesieveResponseCode},
        },
    };

    #[test]
    fn success_returns_ok() {
        let mut space = ManagesieveHaveSpace::new("foobar", 435);

        let bytes = expect_wants_write(&mut space, None);
        assert_eq!(bytes, b"HAVESPACE \"foobar\" 435\r\n");

        expect_wants_read(&mut space);
        expect_complete_ok(&mut space, b"OK\r\n");
    }

    #[test]
    fn a_quota_returns_rejected_error_naming_the_limit() {
        let mut space = ManagesieveHaveSpace::new("myscript", 999999);
        expect_wants_write(&mut space, None);
        expect_wants_read(&mut space);

        let err = expect_complete_err(&mut space, b"NO (QUOTA/MAXSIZE) \"Quota exceeded\"\r\n");
        let ManagesieveHaveSpaceError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(
            completion.code,
            Some(ManagesieveResponseCode::Quota(Some(
                ManagesieveQuota::MaxSize
            )))
        );
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut space = ManagesieveHaveSpace::new("foobar", 1);
        expect_wants_write(&mut space, None);
        expect_wants_read(&mut space);

        let err = expect_complete_err(&mut space, b"");
        assert!(matches!(
            err,
            ManagesieveHaveSpaceError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveHaveSpace, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveHaveSpace) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveHaveSpace, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveHaveSpace,
        reply: &[u8],
    ) -> ManagesieveHaveSpaceError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
