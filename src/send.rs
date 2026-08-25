//! The two base coroutines every command in this crate is built from:
//! read one response, and write one command then read its response.
//!
//! [`ManagesieveResponseRead`] owns the read side alone, because the
//! greeting and the capability refresh following a TLS upgrade arrive
//! unprompted: nothing is written first, and a coroutine that insisted
//! on writing could not read them. [`ManagesieveCommandSend`] is that
//! coroutine with a write in front of it, which is every other command.
//!
//! Both complete on [`ManagesieveResponseReadOk`], which carries the
//! parsed response and whatever arrived past it. The protocol answers
//! one command with exactly one response, so trailing bytes are always
//! a violation; STARTTLS is where acting on them matters, and
//! [`crate::rfc5804::starttls`] is what acts.

use core::{marker::PhantomData, mem};

use alloc::vec::Vec;

use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5804::response::{MAX_LITERAL, ManagesieveResponse, ManagesieveResponseParseError},
    utils::escape_byte_string,
};

/// The bytes a single response may occupy before this crate gives up.
///
/// A response is a literal at most, plus the lines framing it. The
/// ceiling turns a server that never sends a CRLF into a parse error
/// rather than an allocation that grows until the process dies.
pub const MAX_RESPONSE: usize = MAX_LITERAL + 1024 * 1024;

/// Failure causes raised by the two base coroutines.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveCommandSendError {
    /// The stream reached EOF before a complete response arrived.
    #[error("Reached unexpected EOF on ManageSieve stream")]
    Eof,
    /// The server sent more bytes than a single response may occupy.
    #[error("ManageSieve response exceeds {MAX_RESPONSE} bytes")]
    ResponseTooLarge,
    /// The bytes read could not be parsed as a ManageSieve response.
    #[error(transparent)]
    ParseResponse(#[from] ManagesieveResponseParseError),
}

/// Successful output of the two base coroutines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveResponseReadOk {
    /// The parsed response.
    pub response: ManagesieveResponse,
    /// Whatever the server sent past the completion line.
    ///
    /// A non-empty value is a protocol violation, and before a TLS
    /// upgrade it is an injection: the bytes would be replayed inside
    /// the session the upgrade is about to open.
    pub trailing: Vec<u8>,
}

/// I/O-free coroutine reading one ManageSieve response.
pub struct ManagesieveResponseRead {
    wants_read: bool,
    buf: Vec<u8>,
}

impl ManagesieveResponseRead {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            wants_read: false,
            buf: Vec::new(),
        }
    }
}

impl Default for ManagesieveResponseRead {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveResponseRead {
    type Yield = ManagesieveYield;
    type Return = Result<ManagesieveResponseReadOk, ManagesieveCommandSendError>;

    fn resume(
        &mut self,
        mut arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        loop {
            if mem::take(&mut self.wants_read) {
                return ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead);
            }

            match arg.take() {
                Some(&[]) => {
                    let err = ManagesieveCommandSendError::Eof;
                    return ManagesieveCoroutineState::Complete(Err(err));
                }
                Some(data) => {
                    trace!("read bytes: {}", escape_byte_string(data));
                    self.buf.extend_from_slice(data);
                }
                None => {
                    self.wants_read = true;
                    continue;
                }
            }

            let parsed = match ManagesieveResponse::parse(&self.buf) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let err = ManagesieveCommandSendError::ParseResponse(err);
                    return ManagesieveCoroutineState::Complete(Err(err));
                }
            };

            let Some((response, consumed)) = parsed else {
                if self.buf.len() > MAX_RESPONSE {
                    let err = ManagesieveCommandSendError::ResponseTooLarge;
                    return ManagesieveCoroutineState::Complete(Err(err));
                }

                self.wants_read = true;
                continue;
            };

            let trailing = self.buf.split_off(consumed);
            debug!("response complete");
            trace!("{response:?}");

            let out = ManagesieveResponseReadOk { response, trailing };
            return ManagesieveCoroutineState::Complete(Ok(out));
        }
    }
}

/// I/O-free coroutine sending one command and reading its response.
///
/// `Cmd: Into<Vec<u8>>` is satisfied by every `Managesieve*Command`
/// struct in this crate, each of which serialises itself whole,
/// literals included, since the non-synchronising literal ManageSieve
/// gives clients needs no continuation to travel.
pub struct ManagesieveCommandSend<Cmd> {
    bytes: Option<Vec<u8>>,
    read: ManagesieveResponseRead,
    _cmd: PhantomData<Cmd>,
}

impl<Cmd: Into<Vec<u8>>> ManagesieveCommandSend<Cmd> {
    /// Creates the coroutine, serialising `cmd` upfront.
    pub fn new(cmd: Cmd) -> Self {
        Self {
            bytes: Some(cmd.into()),
            read: ManagesieveResponseRead::new(),
            _cmd: PhantomData,
        }
    }
}

impl<Cmd> ManagesieveCoroutine for ManagesieveCommandSend<Cmd> {
    type Yield = ManagesieveYield;
    type Return = Result<ManagesieveResponseReadOk, ManagesieveCommandSendError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        if let Some(bytes) = self.bytes.take() {
            trace!("send bytes: {}", escape_byte_string(&bytes));
            debug!("command sent, awaiting response");
            return ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes));
        }

        self.read.resume(arg)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use crate::{
        coroutine::*,
        rfc5804::response::{ManagesieveResponseParseError, ManagesieveStatus},
        send::*,
    };

    struct Ping;

    impl From<Ping> for Vec<u8> {
        fn from(_: Ping) -> Vec<u8> {
            b"NOOP\r\n".to_vec()
        }
    }

    #[test]
    fn writes_the_command_then_reads_its_response() {
        let mut send = ManagesieveCommandSend::new(Ping);

        let bytes = match send.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };
        assert_eq!(bytes, b"NOOP\r\n");

        assert!(matches!(
            send.resume(None),
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead)
        ));

        let out = match send.resume(Some(b"OK \"NOOP completed\"\r\n")) {
            ManagesieveCoroutineState::Complete(Ok(out)) => out,
            state => panic!("expected Complete(Ok), got {state:?}"),
        };

        assert_eq!(out.response.completion.status, ManagesieveStatus::Ok);
        assert!(out.trailing.is_empty());
    }

    #[test]
    fn reads_a_response_arriving_in_pieces_and_keeps_what_follows() {
        let mut read = ManagesieveResponseRead::new();

        assert!(matches!(
            read.resume(None),
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead)
        ));
        assert!(matches!(
            read.resume(Some(b"\"IMPLEMENTATION\" \"Ex")),
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead)
        ));

        let out = match read.resume(Some(b"ample1\"\r\nOK\r\nNOOP\r\n")) {
            ManagesieveCoroutineState::Complete(Ok(out)) => out,
            state => panic!("expected Complete(Ok), got {state:?}"),
        };

        assert_eq!(out.response.data.len(), 1);
        assert_eq!(out.trailing, b"NOOP\r\n");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut read = ManagesieveResponseRead::new();
        read.resume(None);

        let err = match read.resume(Some(b"")) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        };

        assert_eq!(err, ManagesieveCommandSendError::Eof);
    }

    #[test]
    fn a_response_that_never_ends_returns_a_too_large_error() {
        let mut read = ManagesieveResponseRead::new();
        read.resume(None);

        // NOTE: no CRLF anywhere, so nothing can ever complete and the
        // buffer would otherwise grow for as long as the server writes.
        let flood = vec![b'x'; MAX_RESPONSE + 1];
        let err = match read.resume(Some(&flood)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        };

        assert_eq!(err, ManagesieveCommandSendError::ResponseTooLarge);
    }

    #[test]
    fn a_malformed_response_returns_a_parse_error() {
        let mut read = ManagesieveResponseRead::new();
        read.resume(None);

        let err = match read.resume(Some(b"MAYBE\r\n")) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        };

        assert!(matches!(
            err,
            ManagesieveCommandSendError::ParseResponse(
                ManagesieveResponseParseError::UnknownStatus(_)
            )
        ));
    }
}
