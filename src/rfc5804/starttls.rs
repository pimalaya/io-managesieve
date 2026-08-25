//! The STARTTLS command, upgrading a cleartext connection ([RFC 5804
//! section 2.2]).
//!
//! The coroutine stops at the OK ending the command. The TLS handshake
//! is the caller's, and so is reading the capability response the
//! server sends once the layer is up, which is another greeting and is
//! read by [`crate::rfc5804::greeting`]. The cached capabilities are
//! discarded rather than merged: the specification says the pre-upgrade
//! list may differ, and trusting it is what STARTTLS exists to prevent.
//!
//! Bytes arriving past the OK end the exchange in an error rather than
//! reaching the caller. Nothing legitimate follows, the client is
//! forbidden from writing until the handshake completes, and a
//! coroutine handing the bytes back would be inviting a caller to
//! upgrade anyway.
//!
//! [RFC 5804 section 2.2]: https://www.rfc-editor.org/rfc/rfc5804#section-2.2
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
//!     rfc5804::starttls::ManagesieveStartTls,
//! };
//!
//! // Ready stream needed (TCP-connected, greeting read, cleartext)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ManagesieveStartTls::new();
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
//!
//! // Now upgrade `stream` to TLS, then read the new capabilities with
//! // ManagesieveGreetingGet.
//! ```

use core::fmt;

use alloc::vec::Vec;

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, managesieve_try, rfc5804::response::ManagesieveCompletion, send::*};

/// The STARTTLS command ([RFC 5804 section 2.2]).
///
/// [RFC 5804 section 2.2]: https://www.rfc-editor.org/rfc/rfc5804#section-2.2
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveStartTlsCommand;

impl From<ManagesieveStartTlsCommand> for Vec<u8> {
    fn from(_: ManagesieveStartTlsCommand) -> Vec<u8> {
        b"STARTTLS\r\n".to_vec()
    }
}

/// Failure causes during the ManageSieve STARTTLS exchange.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveStartTlsError {
    /// The server refused the upgrade.
    #[error("ManageSieve STARTTLS failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// The server sent bytes past the OK.
    ///
    /// RFC 5804 section 2.2 forbids the client from writing until the
    /// handshake completes, so their presence means an attacker
    /// injected commands the server would replay inside the TLS
    /// session. The upgrade is refused rather than performed.
    #[error("ManageSieve STARTTLS reply carried trailing bytes: refusing the TLS upgrade")]
    Injection,
    /// The underlying command exchange failed.
    #[error("ManageSieve STARTTLS failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve STARTTLS coroutine.
pub struct ManagesieveStartTls {
    state: State,
}

impl ManagesieveStartTls {
    /// Creates the coroutine.
    pub fn new() -> Self {
        let send = ManagesieveCommandSend::new(ManagesieveStartTlsCommand);
        Self {
            state: State::Send(send),
        }
    }
}

impl Default for ManagesieveStartTls {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagesieveCoroutine for ManagesieveStartTls {
    type Yield = ManagesieveYield;
    type Return = Result<(), ManagesieveStartTlsError>;

    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = managesieve_try!(send, arg);

                if !out.trailing.is_empty() {
                    let err = ManagesieveStartTlsError::Injection;
                    return ManagesieveCoroutineState::Complete(Err(err));
                }

                match out.response.into_result() {
                    Ok(_) => {
                        debug!("starttls accepted, ready to upgrade");
                        ManagesieveCoroutineState::Complete(Ok(()))
                    }
                    Err(completion) => {
                        let err = ManagesieveStartTlsError::Rejected(completion);
                        ManagesieveCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ManagesieveCommandSend<ManagesieveStartTlsCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send starttls"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc5804::starttls::*};

    #[test]
    fn success_returns_ok() {
        let mut starttls = ManagesieveStartTls::new();

        let bytes = expect_wants_write(&mut starttls, None);
        assert_eq!(bytes, b"STARTTLS\r\n");

        expect_wants_read(&mut starttls);
        expect_complete_ok(&mut starttls, b"OK\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut starttls = ManagesieveStartTls::new();
        expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let err = expect_complete_err(&mut starttls, b"NO \"TLS not available\"\r\n");
        let ManagesieveStartTlsError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(completion.to_string(), "NO TLS not available");
    }

    #[test]
    fn trailing_bytes_refuse_the_upgrade() {
        let mut starttls = ManagesieveStartTls::new();
        expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        // NOTE: the injected command rides in the same segment as the
        // OK, so the server would replay it inside the TLS session.
        let err = expect_complete_err(&mut starttls, b"OK\r\nNOOP\r\n");
        assert_eq!(err, ManagesieveStartTlsError::Injection);
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut starttls = ManagesieveStartTls::new();
        expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let err = expect_complete_err(&mut starttls, b"");
        assert!(matches!(
            err,
            ManagesieveStartTlsError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut ManagesieveStartTls, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveStartTls) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ManagesieveStartTls, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveStartTls,
        reply: &[u8],
    ) -> ManagesieveStartTlsError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
