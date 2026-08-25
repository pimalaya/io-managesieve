//! The AUTHENTICATE command, the one exchange in the protocol with a
//! shape of its own ([RFC 5804 section 2.1]).
//!
//! One coroutine covers every mechanism, unlike io-imap and io-smtp
//! which carry a file per mechanism. Those two frame each mechanism
//! differently, IMAP through the `AuthMechanism` grammar of imap-types
//! and SMTP through the AUTH command plus a per-mechanism capability
//! refresh. ManageSieve frames them all identically: a mechanism name
//! and a base64 string out, a base64 string back, until the server
//! answers OK. So the mechanism is a value here rather than a module,
//! and adding one to io-sasl adds one arm.
//!
//! That also makes the server-first mechanisms free. A mechanism
//! answering the first resume with `WantsRead` has nothing to inline,
//! so the command goes out bare and the server's first challenge is fed
//! back; CRAM-MD5 is the one that needs it, and no protocol crate had
//! it before this one.
//!
//! Two mechanisms are refused rather than framed. GSSAPI and GS2-KRB5
//! are relays: what they answer is not the server's challenge but what
//! the caller's own security context made of it, so framing them takes
//! a yield vocabulary this coroutine does not have. They are named in
//! the error rather than silently skipped.
//!
//! The exchange is cancelled properly when a mechanism refuses what the
//! server said. RFC 5804 section 2.1 gives clients the `"*"` string for
//! it, and sending it leaves a session the caller can keep using
//! instead of a stream out of step with its server.
//!
//! [RFC 5804 section 2.1]: https://www.rfc-editor.org/rfc/rfc5804#section-2.1
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
//!     rfc5804::authenticate::{ManagesieveAuthenticate, ManagesieveAuthenticateOptions},
//! };
//! use io_sasl::rfc4616::plain::SaslPlainCreds;
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, greeting read)
//! let mut stream = TcpStream::connect("localhost:4190").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let creds = SaslPlainCreds {
//!     authzid: None,
//!     authcid: String::from("alice"),
//!     passwd: String::from("secret").into(),
//! };
//!
//! let opts = ManagesieveAuthenticateOptions {
//!     initial_response: true,
//!     ..Default::default()
//! };
//!
//! let mut coroutine = ManagesieveAuthenticate::new(creds, opts);
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
//!         ManagesieveCoroutineState::Complete(Ok(_capabilities)) => break,
//!         ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{fmt, mem};

use alloc::{boxed::Box, vec::Vec};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
#[cfg(feature = "cram-md5")]
use io_sasl::rfc2195::cram_md5::{SaslCramMd5, SaslCramMd5Error};
use io_sasl::{
    coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
    login::{SaslLogin, SaslLoginError},
    mechanism::{Sasl, SaslMechanism},
    rfc4422::external::{SaslExternal, SaslExternalError},
    rfc4505::anonymous::{SaslAnonymous, SaslAnonymousError},
    rfc4616::plain::{SaslPlain, SaslPlainError},
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerError},
    xoauth2::{SaslXoauth2, SaslXoauth2Error},
};
#[cfg(feature = "scram")]
use io_sasl::{
    rfc5802::{SaslScramError, scram_sha_1::SaslScramSha1},
    rfc7677::scram_sha_256::SaslScramSha256,
    scram_sha_512::SaslScramSha512,
};
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    managesieve_try,
    rfc5804::{
        capability::{
            ManagesieveCapabilities, ManagesieveCapabilityGet, ManagesieveCapabilityGetError,
        },
        response::{
            ManagesieveCompletion, ManagesieveLine, ManagesieveResponseCode,
            ManagesieveResponseParseError, ManagesieveStatus,
        },
    },
    send::{MAX_RESPONSE, ManagesieveCommandSendError},
    utils::string,
};

/// The AUTHENTICATE command ([RFC 5804 section 2.1]).
///
/// [RFC 5804 section 2.1]: https://www.rfc-editor.org/rfc/rfc5804#section-2.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveAuthenticateCommand {
    /// The mechanism to run, named as IANA registered it.
    pub mechanism: SaslMechanism,
    /// The mechanism's initial response, raw rather than base64.
    ///
    /// Inlining it saves the round trip of the empty challenge, and is
    /// only valid for a mechanism that speaks first.
    pub initial_response: Option<Vec<u8>>,
}

impl From<ManagesieveAuthenticateCommand> for Vec<u8> {
    fn from(cmd: ManagesieveAuthenticateCommand) -> Vec<u8> {
        let mut bytes = b"AUTHENTICATE ".to_vec();

        bytes.extend(string(cmd.mechanism.as_str().as_bytes()));

        if let Some(response) = cmd.initial_response {
            bytes.push(b' ');
            bytes.extend(string(base64.encode(response).as_bytes()));
        }

        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

/// Options for [`ManagesieveAuthenticate::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagesieveAuthenticateOptions {
    /// Inline the mechanism's initial response with the command,
    /// saving the round trip of the empty challenge.
    ///
    /// Unlike IMAP, which needs the RFC 4959 capability for this, the
    /// ManageSieve grammar carries an initial response unconditionally,
    /// so a caller can turn it on against any server. A mechanism that
    /// speaks second ignores it.
    pub initial_response: bool,
    /// Read the capabilities again once authentication succeeds.
    ///
    /// A server may change them: OWNER only appears authenticated, and
    /// LANGUAGE and MAXREDIRECTS may be per-user. Off by default, since
    /// it costs a round trip a caller may not need.
    pub ensure_capabilities: bool,
}

/// Failure causes during the ManageSieve AUTHENTICATE exchange.
#[derive(Debug, Error)]
pub enum ManagesieveAuthenticateError {
    /// The server refused the exchange, AUTH-TOO-WEAK, ENCRYPT-NEEDED
    /// and TRANSITION-NEEDED being the codes to expect.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Rejected(ManagesieveCompletion),
    /// Credentials were given for a mechanism this crate does not
    /// frame.
    ///
    /// io-sasl computes more mechanisms than this crate wires up: the
    /// two Kerberos relays answer with what the caller's security
    /// context produced rather than with what the server sent, which
    /// takes a yield vocabulary this coroutine does not have. They are
    /// named rather than silently skipped.
    #[error("ManageSieve AUTHENTICATE failed: {} mechanism is not supported by this crate", .0.as_str())]
    UnsupportedMechanism(SaslMechanism),
    /// The server answered OK before the mechanism sent anything.
    #[error("ManageSieve AUTHENTICATE failed: server returned OK before the mechanism could send")]
    UnexpectedOk,
    /// A challenge line was not one string.
    #[error("ManageSieve AUTHENTICATE failed: malformed server challenge")]
    InvalidChallenge,
    /// A challenge or a final SASL response was not valid base64.
    #[error("ManageSieve AUTHENTICATE failed: invalid base64 in server challenge")]
    InvalidBase64,
    /// The SASL ANONYMOUS mechanism failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Anonymous(#[from] SaslAnonymousError),
    /// The SASL CRAM-MD5 mechanism failed.
    #[cfg(feature = "cram-md5")]
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    CramMd5(#[from] SaslCramMd5Error),
    /// The SASL EXTERNAL mechanism failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    External(#[from] SaslExternalError),
    /// The SASL LOGIN mechanism failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Login(#[from] SaslLoginError),
    /// The SASL PLAIN mechanism failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Plain(#[from] SaslPlainError),
    /// The SASL OAUTHBEARER mechanism failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Oauthbearer(#[from] SaslOauthbearerError),
    /// The SASL XOAUTH2 mechanism failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Xoauth2(#[from] SaslXoauth2Error),
    /// A SASL SCRAM profile failed.
    #[cfg(feature = "scram")]
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Scram(#[from] SaslScramError),
    /// The follow-up CAPABILITY command failed.
    #[error(transparent)]
    Capability(#[from] ManagesieveCapabilityGetError),
    /// The response could not be parsed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    ParseResponse(#[from] ManagesieveResponseParseError),
    /// The underlying exchange failed.
    #[error("ManageSieve AUTHENTICATE failed: {0}")]
    Send(#[from] ManagesieveCommandSendError),
}

/// I/O-free ManageSieve AUTHENTICATE coroutine.
pub struct ManagesieveAuthenticate {
    state: State,
    sasl: Option<Sasl>,
    mechanism: Option<Box<Mechanism>>,
    buf: Vec<u8>,
    wants_read: bool,
    capabilities: ManagesieveCapabilities,
    opts: ManagesieveAuthenticateOptions,
}

impl ManagesieveAuthenticate {
    /// Builds an AUTHENTICATE coroutine running the mechanism `sasl`
    /// describes.
    ///
    /// Anything converting into a [`Sasl`] is accepted, so a caller
    /// passes the per-mechanism credential struct directly. A SCRAM
    /// exchange draws nothing here: its client nonce travels with the
    /// credentials, so this coroutine stays free of both I/O and
    /// randomness.
    pub fn new(sasl: impl Into<Sasl>, opts: ManagesieveAuthenticateOptions) -> Self {
        Self {
            state: State::Start,
            sasl: Some(sasl.into()),
            mechanism: None,
            buf: Vec::new(),
            wants_read: false,
            capabilities: ManagesieveCapabilities::default(),
            opts,
        }
    }

    /// Advances the mechanism one step, mapping its yield onto the
    /// payload to write, if any.
    ///
    /// [`None`] covers both a mechanism waiting for the server and one
    /// that has finished speaking, which the framing answers the same
    /// way: with nothing.
    fn resume_sasl(
        &mut self,
        arg: SaslArg<'_>,
    ) -> Result<Option<Vec<u8>>, ManagesieveAuthenticateError> {
        let Some(mechanism) = self.mechanism.as_mut() else {
            return Ok(None);
        };

        mechanism.resume(arg)
    }

    /// Reads one logical line out of the buffer, or asks for more.
    fn take_line(&mut self) -> Result<Option<ManagesieveLine>, ManagesieveAuthenticateError> {
        let Some((line, consumed)) = ManagesieveLine::parse(&self.buf)? else {
            if self.buf.len() > MAX_RESPONSE {
                let err = ManagesieveCommandSendError::ResponseTooLarge;
                return Err(err.into());
            }

            self.wants_read = true;
            return Ok(None);
        };

        self.buf.drain(..consumed);
        Ok(Some(line))
    }

    /// Whether the reply to a cancelled exchange has arrived, or
    /// whatever came instead is past reading.
    ///
    /// The reply itself is thrown away: what the caller needs is why
    /// the mechanism refused, and reading it is only what leaves the
    /// session usable.
    fn saw_cancellation_reply(&mut self) -> bool {
        loop {
            match ManagesieveLine::parse(&self.buf) {
                Ok(Some((line, consumed))) => {
                    self.buf.drain(..consumed);

                    if matches!(line, ManagesieveLine::Completion(_)) {
                        return true;
                    }
                }
                Ok(None) => return self.buf.len() > MAX_RESPONSE,
                Err(_) => return true,
            }
        }
    }

    /// Frames a client response: base64, then a ManageSieve string.
    fn client_response(payload: &[u8]) -> Vec<u8> {
        let mut bytes = string(base64.encode(payload).as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes
    }

    /// Decides what to do once the server ended the exchange.
    fn complete(
        &mut self,
        completion: ManagesieveCompletion,
        pending: bool,
    ) -> Result<Option<State>, ManagesieveAuthenticateError> {
        if completion.status != ManagesieveStatus::Ok {
            return Err(ManagesieveAuthenticateError::Rejected(completion));
        }

        // NOTE: with nothing inlined, a server finishing here never
        // asked for what it claims to have authenticated.
        if pending {
            return Err(ManagesieveAuthenticateError::UnexpectedOk);
        }

        // NOTE: the final server data may ride in the SASL response
        // code to save a round trip, and a mutual mechanism needs it
        // before it can be told the exchange is over.
        if let Some(ManagesieveResponseCode::Sasl(data)) = &completion.code {
            let data = base64
                .decode(data)
                .map_err(|_| ManagesieveAuthenticateError::InvalidBase64)?;

            self.resume_sasl(SaslArg::Input(&data))?;
        }

        // NOTE: the mechanism is told the exchange ended rather than
        // dropped: one performing mutual authentication refuses here
        // when it verified nothing, which is what stops a success reply
        // from standing in for a proof the server never gave.
        self.resume_sasl(SaslArg::Done)?;

        let next = self
            .opts
            .ensure_capabilities
            .then(|| State::Capability(ManagesieveCapabilityGet::new()));

        Ok(next)
    }
}

impl ManagesieveCoroutine for ManagesieveAuthenticate {
    type Yield = ManagesieveYield;
    type Return = Result<ManagesieveCapabilities, ManagesieveAuthenticateError>;

    fn resume(
        &mut self,
        mut arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return> {
        loop {
            if mem::take(&mut self.wants_read) {
                return ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead);
            }

            match &mut self.state {
                State::Start => {
                    let sasl = self.sasl.take().expect("credentials taken twice");

                    let mechanism = match Mechanism::new(sasl) {
                        Ok(mechanism) => mechanism,
                        Err(err) => return ManagesieveCoroutineState::Complete(Err(err)),
                    };

                    let name = mechanism.mechanism();
                    self.mechanism = Some(Box::new(mechanism));

                    let payload = match self.resume_sasl(SaslArg::None) {
                        Ok(payload) => payload,
                        Err(err) => return ManagesieveCoroutineState::Complete(Err(err)),
                    };

                    // NOTE: draft-murchison-sasl-login is server-first,
                    // prompting for the username, even though io-sasl
                    // computes that username without a challenge.
                    // Inlining it would be an initial response for a
                    // mechanism sending data in the initial challenge,
                    // which RFC 5804 section 2.1 tells servers to
                    // reject.
                    let inline = self.opts.initial_response && name != SaslMechanism::Login;

                    let (initial_response, pending) = match payload {
                        Some(payload) if inline => (Some(payload), None),
                        payload => (None, payload),
                    };

                    let cmd = ManagesieveAuthenticateCommand {
                        mechanism: name,
                        initial_response,
                    };

                    self.state = State::Write {
                        bytes: cmd.into(),
                        pending,
                    };
                    debug!("{}", self.state);
                }
                State::Write { bytes, pending } => {
                    let bytes = mem::take(bytes);
                    let pending = pending.take();

                    self.state = State::Read { pending };
                    debug!("{}", self.state);

                    return ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes));
                }
                State::Read { pending } => {
                    let mut pending = pending.take();

                    // NOTE: a resume carrying nothing still looks at the
                    // buffer first, since a line the last read went
                    // past is already there and asking for another read
                    // would wait for bytes the server has no reason to
                    // send.
                    match arg.take() {
                        Some(&[]) => {
                            let err = ManagesieveCommandSendError::Eof.into();
                            return ManagesieveCoroutineState::Complete(Err(err));
                        }
                        Some(data) => {
                            trace!("read {} bytes", data.len());
                            self.buf.extend_from_slice(data);
                        }
                        None => {}
                    }

                    let line = match self.take_line() {
                        Ok(Some(line)) => line,
                        Ok(None) => {
                            self.state = State::Read { pending };
                            continue;
                        }
                        Err(err) => return ManagesieveCoroutineState::Complete(Err(err)),
                    };

                    let completion = match line {
                        ManagesieveLine::Completion(completion) => completion,
                        ManagesieveLine::Data(line) => {
                            let Some(challenge) = line.string(0) else {
                                let err = ManagesieveAuthenticateError::InvalidChallenge;
                                return ManagesieveCoroutineState::Complete(Err(err));
                            };

                            // NOTE: the challenge a mechanism that
                            // already spoke answers is the empty one, so
                            // it is answered from what the mechanism
                            // yielded rather than fed back to it.
                            let payload = match pending.take() {
                                Some(payload) => Ok(Some(payload)),
                                None => match base64.decode(challenge) {
                                    Ok(challenge) => self.resume_sasl(SaslArg::Input(&challenge)),
                                    Err(_) => Err(ManagesieveAuthenticateError::InvalidBase64),
                                },
                            };

                            self.state = match payload {
                                Ok(payload) => State::Write {
                                    bytes: Self::client_response(&payload.unwrap_or_default()),
                                    pending: None,
                                },
                                Err(err) => State::Cancel { error: Some(err) },
                            };

                            debug!("{}", self.state);
                            continue;
                        }
                    };

                    match self.complete(completion, pending.is_some()) {
                        Err(err) => return ManagesieveCoroutineState::Complete(Err(err)),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                        Ok(None) => {
                            debug!("authenticated");
                            let capabilities = mem::take(&mut self.capabilities);
                            return ManagesieveCoroutineState::Complete(Ok(capabilities));
                        }
                    }
                }
                State::Cancel { error } => {
                    self.state = State::Abort {
                        error: error.take(),
                    };
                    debug!("{}", self.state);

                    let bytes = b"\"*\"\r\n".to_vec();
                    return ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes));
                }
                State::Abort { error } => {
                    let mut error = error.take();
                    let eof = matches!(arg, Some(&[]));

                    if let Some(data) = arg.take() {
                        trace!("read {} bytes", data.len());
                        self.buf.extend_from_slice(data);
                    }

                    // NOTE: a connection dying under the cancellation is
                    // not worth reporting over the failure that caused
                    // it, so EOF ends the wait rather than replacing the
                    // cause.
                    if !eof && !self.saw_cancellation_reply() {
                        self.state = State::Abort { error };
                        self.wants_read = true;
                        continue;
                    }

                    let err = error.take().expect("cancellation cause taken twice");
                    return ManagesieveCoroutineState::Complete(Err(err));
                }
                State::Capability(capability) => {
                    let capabilities = managesieve_try!(capability, arg);
                    debug!("authenticated");

                    return ManagesieveCoroutineState::Complete(Ok(capabilities));
                }
            }
        }
    }
}

enum State {
    Start,
    Write {
        bytes: Vec<u8>,
        pending: Option<Vec<u8>>,
    },
    Read {
        pending: Option<Vec<u8>>,
    },
    Cancel {
        error: Option<ManagesieveAuthenticateError>,
    },
    Abort {
        error: Option<ManagesieveAuthenticateError>,
    },
    Capability(ManagesieveCapabilityGet),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("start mechanism"),
            Self::Write { pending, .. } if pending.is_some() => f.write_str("send auth"),
            Self::Write { .. } => f.write_str("send auth response"),
            Self::Read { .. } => f.write_str("read challenge"),
            Self::Cancel { .. } => f.write_str("cancel exchange"),
            Self::Abort { .. } => f.write_str("read cancellation reply"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
        }
    }
}

/// The mechanisms this crate frames, one arm per [`Sasl`] variant it
/// accepts.
enum Mechanism {
    Anonymous(SaslAnonymous),
    #[cfg(feature = "cram-md5")]
    CramMd5(SaslCramMd5),
    External(SaslExternal),
    Login(SaslLogin),
    Plain(SaslPlain),
    Oauthbearer(SaslOauthbearer),
    Xoauth2(SaslXoauth2),
    #[cfg(feature = "scram")]
    ScramSha1(SaslScramSha1),
    #[cfg(feature = "scram")]
    ScramSha256(SaslScramSha256),
    #[cfg(feature = "scram")]
    ScramSha512(SaslScramSha512),
}

impl Mechanism {
    /// Builds the mechanism `sasl` describes.
    fn new(sasl: Sasl) -> Result<Self, ManagesieveAuthenticateError> {
        let mechanism = match sasl {
            Sasl::Anonymous(creds) => Self::Anonymous(SaslAnonymous::new(creds)),
            #[cfg(feature = "cram-md5")]
            Sasl::CramMd5(creds) => Self::CramMd5(SaslCramMd5::new(creds)),
            Sasl::External(creds) => Self::External(SaslExternal::new(creds)),
            Sasl::Login(creds) => Self::Login(SaslLogin::new(creds)),
            Sasl::Plain(creds) => Self::Plain(SaslPlain::new(creds)),
            Sasl::Oauthbearer(creds) => Self::Oauthbearer(SaslOauthbearer::new(creds)),
            Sasl::Xoauth2(creds) => Self::Xoauth2(SaslXoauth2::new(creds)),
            #[cfg(feature = "scram")]
            Sasl::ScramSha1(creds) => Self::ScramSha1(SaslScramSha1::new(creds)),
            #[cfg(feature = "scram")]
            Sasl::ScramSha256(creds) => Self::ScramSha256(SaslScramSha256::new(creds)),
            #[cfg(feature = "scram")]
            Sasl::ScramSha512(creds) => Self::ScramSha512(SaslScramSha512::new(creds)),
            // NOTE: the Kerberos relays land here, and so does whatever
            // io-sasl gains under a feature this crate does not enable
            // but another crate in the build does.
            sasl => {
                let mechanism = sasl.mechanism();
                return Err(ManagesieveAuthenticateError::UnsupportedMechanism(
                    mechanism,
                ));
            }
        };

        Ok(mechanism)
    }

    /// The tag naming this mechanism on the wire.
    fn mechanism(&self) -> SaslMechanism {
        match self {
            Self::Anonymous(mechanism) => mechanism.mechanism(),
            #[cfg(feature = "cram-md5")]
            Self::CramMd5(mechanism) => mechanism.mechanism(),
            Self::External(mechanism) => mechanism.mechanism(),
            Self::Login(mechanism) => mechanism.mechanism(),
            Self::Plain(mechanism) => mechanism.mechanism(),
            Self::Oauthbearer(mechanism) => mechanism.mechanism(),
            Self::Xoauth2(mechanism) => mechanism.mechanism(),
            #[cfg(feature = "scram")]
            Self::ScramSha1(mechanism) => mechanism.mechanism(),
            #[cfg(feature = "scram")]
            Self::ScramSha256(mechanism) => mechanism.mechanism(),
            #[cfg(feature = "scram")]
            Self::ScramSha512(mechanism) => mechanism.mechanism(),
        }
    }

    /// Advances the mechanism, normalising its yield and its failure.
    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> Result<Option<Vec<u8>>, ManagesieveAuthenticateError> {
        match self {
            Self::Anonymous(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            #[cfg(feature = "cram-md5")]
            Self::CramMd5(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            Self::External(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            Self::Login(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            Self::Plain(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            Self::Oauthbearer(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            Self::Xoauth2(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            #[cfg(feature = "scram")]
            Self::ScramSha1(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            #[cfg(feature = "scram")]
            Self::ScramSha256(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
            #[cfg(feature = "scram")]
            Self::ScramSha512(mechanism) => step(mechanism.resume(arg)).map_err(Into::into),
        }
    }
}

/// Turns one mechanism step into the payload it wants written.
///
/// A mechanism waiting for the server and one that has finished
/// speaking both answer [`None`], which the framing treats the same
/// way: it writes nothing of its own.
fn step<E>(state: SaslCoroutineState<SaslYield, Result<(), E>>) -> Result<Option<Vec<u8>>, E> {
    match state {
        SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
        SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
        SaslCoroutineState::Complete(result) => result.map(|()| None),
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use io_sasl::{login::SaslLoginCreds, rfc4616::plain::SaslPlainCreds};
    use secrecy::SecretString;

    use crate::{coroutine::*, rfc5804::authenticate::*};

    #[test]
    fn initial_response_success_returns_ok() {
        let opts = ManagesieveAuthenticateOptions {
            initial_response: true,
            ..Default::default()
        };

        let mut auth = ManagesieveAuthenticate::new(plain(), opts);

        let bytes = expect_wants_write(&mut auth, None);
        assert_eq!(
            bytes,
            b"AUTHENTICATE \"PLAIN\" \"AGFsaWNlAHNlY3JldA==\"\r\n"
        );

        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"OK\r\n");
    }

    #[test]
    fn plain_without_initial_response_answers_the_empty_challenge() {
        let mut auth = ManagesieveAuthenticate::new(plain(), Default::default());

        let bytes = expect_wants_write(&mut auth, None);
        assert_eq!(bytes, b"AUTHENTICATE \"PLAIN\"\r\n");

        expect_wants_read(&mut auth);

        let creds = expect_wants_write(&mut auth, Some(b"\"\"\r\n"));
        assert_eq!(creds, b"\"AGFsaWNlAHNlY3JldA==\"\r\n");

        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"OK\r\n");
    }

    #[test]
    fn a_read_carrying_more_than_one_line_is_drained_before_asking_for_another() {
        let mut auth = ManagesieveAuthenticate::new(plain(), Default::default());

        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: the empty challenge and the completion arrive in one
        // read, which a server has no reason to do and a proxy or a
        // test double very well might.
        let creds = expect_wants_write(&mut auth, Some(b"\"\"\r\nOK\r\n"));
        assert_eq!(creds, b"\"AGFsaWNlAHNlY3JldA==\"\r\n");

        // NOTE: the completion is already buffered, so the exchange
        // ends here rather than waiting for bytes nobody will send.
        match auth.resume(None) {
            ManagesieveCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn an_ok_before_the_credentials_returns_unexpected_ok_error() {
        let mut auth = ManagesieveAuthenticate::new(plain(), Default::default());
        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"OK\r\n");
        assert!(matches!(err, ManagesieveAuthenticateError::UnexpectedOk));
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let opts = ManagesieveAuthenticateOptions {
            initial_response: true,
            ..Default::default()
        };

        let mut auth = ManagesieveAuthenticate::new(plain(), opts);
        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"NO (ENCRYPT-NEEDED) \"Use TLS\"\r\n");
        let ManagesieveAuthenticateError::Rejected(completion) = err else {
            panic!("expected Rejected, got {err:?}");
        };

        assert_eq!(
            completion.code,
            Some(ManagesieveResponseCode::EncryptNeeded)
        );
    }

    #[test]
    fn an_extra_challenge_cancels_the_exchange_and_reports_the_mechanism() {
        let opts = ManagesieveAuthenticateOptions {
            initial_response: true,
            ..Default::default()
        };

        let mut auth = ManagesieveAuthenticate::new(plain(), opts);
        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: PLAIN has nothing left to answer once its credentials
        // went inline, so the refusal is the mechanism's; the exchange
        // is cancelled with the "*" string RFC 5804 section 2.1 gives
        // clients, which leaves the session usable.
        let cancel = expect_wants_write(&mut auth, Some(b"\"\"\r\n"));
        assert_eq!(cancel, b"\"*\"\r\n");

        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"NO \"Authentication aborted\"\r\n");
        assert!(matches!(
            err,
            ManagesieveAuthenticateError::Plain(SaslPlainError::UnexpectedChallenge)
        ));
    }

    #[test]
    fn ensure_capabilities_reads_them_back() {
        let opts = ManagesieveAuthenticateOptions {
            initial_response: true,
            ensure_capabilities: true,
        };

        let mut auth = ManagesieveAuthenticate::new(plain(), opts);
        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let command = expect_wants_write(&mut auth, Some(b"OK\r\n"));
        assert_eq!(command, b"CAPABILITY\r\n");

        expect_wants_read(&mut auth);

        let reply = b"\"OWNER\" \"alice@example.org\"\r\nOK\r\n";
        let capabilities = expect_complete_ok(&mut auth, reply);

        assert_eq!(capabilities.owner().unwrap(), "alice@example.org");
    }

    #[test]
    fn a_malformed_challenge_returns_invalid_base64_error() {
        let mut auth = ManagesieveAuthenticate::new(login(), Default::default());
        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: LOGIN speaks second here, so the challenge is fed to the
        // mechanism and has to decode first.
        expect_wants_write(&mut auth, Some(b"\"VXNlcm5hbWU6\"\r\n"));
        expect_wants_read(&mut auth);

        let cancel = expect_wants_write(&mut auth, Some(b"\"not base64!!\"\r\n"));
        assert_eq!(cancel, b"\"*\"\r\n");

        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"NO \"aborted\"\r\n");
        assert!(matches!(err, ManagesieveAuthenticateError::InvalidBase64));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut auth = ManagesieveAuthenticate::new(plain(), Default::default());
        expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            ManagesieveAuthenticateError::Send(ManagesieveCommandSendError::Eof)
        ));
    }

    fn plain() -> SaslPlainCreds {
        SaslPlainCreds {
            authzid: None,
            authcid: String::from("alice"),
            passwd: SecretString::from("secret"),
        }
    }

    fn login() -> SaslLoginCreds {
        SaslLoginCreds {
            username: String::from("alice"),
            password: SecretString::from("secret"),
        }
    }

    fn expect_wants_write(cor: &mut ManagesieveAuthenticate, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ManagesieveAuthenticate) {
        match cor.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ManagesieveAuthenticate,
        reply: &[u8],
    ) -> ManagesieveCapabilities {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Ok(capabilities)) => capabilities,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ManagesieveAuthenticate,
        reply: &[u8],
    ) -> ManagesieveAuthenticateError {
        match cor.resume(Some(reply)) {
            ManagesieveCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
