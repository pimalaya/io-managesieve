//! # ManageSieve client surfaces
//!
//! Two traits and one implementation of them. [`ManagesieveClient`] and
//! [`ManagesieveClientAsync`] carry the command surface: implement one
//! `run` method that pumps a coroutine against your transport, and
//! inherit every command. [`ManagesieveClientStd`] is the opinionated
//! blocking implementation, holding a single stream (any blocking
//! `Read + Write` impl).
//!
//! ManageSieve keeps no session context worth caching here: the
//! capabilities are returned by [`greeting`], [`capability`] and
//! [`authenticate`] and consumed by the caller, and every other
//! coroutine is stateless.
//!
//! The bare [`new`] constructor takes a pre-connected stream; callers
//! handle TCP and TLS themselves. With one of the TLS feature flags
//! enabled (`rustls-ring`, `rustls-aws`, `native-tls`), [`connect`] is
//! also available and produces a ready-to-use authenticated client
//! end-to-end. It owns no protocol logic of its own: the ordering, the
//! scheme table and the cleartext-credential policy all live in
//! [`ManagesieveSessionOpen`], and [`connect`] only answers its
//! transport, read and write requests with a [`Stream`].
//!
//! [`ManagesieveSessionOpen`]: crate::session::ManagesieveSessionOpen
//! [`Stream`]: pimalaya_stream::stream::Stream
//! [`new`]: ManagesieveClientStd::new
//! [`connect`]: ManagesieveClientStd::connect
//! [`greeting`]: ManagesieveClient::greeting
//! [`capability`]: ManagesieveClient::capability
//! [`authenticate`]: ManagesieveClient::authenticate

use core::{any::Any, fmt, future::Future};

use alloc::{boxed::Box, string::String, vec::Vec};

use std::io::{self, Read, Write};

use io_sasl::mechanism::Sasl;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5804::{
        authenticate::*, capability::*, checkscript::*, deletescript::*, getscript::*, greeting::*,
        havespace::*, listscripts::*, logout::*, noop::*, putscript::*, raw::*, renamescript::*,
        response::ManagesieveResponse, setactive::*, starttls::*, unauthenticate::*,
    },
    session::*,
};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
mod connect;

/// Errors returned by the client surfaces.
#[derive(Debug, Error)]
pub enum ManagesieveClientError {
    /// The greeting coroutine failed.
    #[error(transparent)]
    Greeting(#[from] ManagesieveGreetingGetError),
    /// The CAPABILITY coroutine failed.
    #[error(transparent)]
    Capability(#[from] ManagesieveCapabilityGetError),
    /// The STARTTLS coroutine failed.
    #[error(transparent)]
    StartTls(#[from] ManagesieveStartTlsError),
    /// The AUTHENTICATE coroutine failed.
    #[error(transparent)]
    Authenticate(#[from] ManagesieveAuthenticateError),
    /// The LOGOUT coroutine failed.
    #[error(transparent)]
    Logout(#[from] ManagesieveLogoutError),
    /// The NOOP coroutine failed.
    #[error(transparent)]
    Noop(#[from] ManagesieveNoopError),
    /// The UNAUTHENTICATE coroutine failed.
    #[error(transparent)]
    Unauthenticate(#[from] ManagesieveUnauthenticateError),
    /// The HAVESPACE coroutine failed.
    #[error(transparent)]
    HaveSpace(#[from] ManagesieveHaveSpaceError),
    /// The LISTSCRIPTS coroutine failed.
    #[error(transparent)]
    ScriptList(#[from] ManagesieveScriptListError),
    /// The GETSCRIPT coroutine failed.
    #[error(transparent)]
    ScriptGet(#[from] ManagesieveScriptGetError),
    /// The PUTSCRIPT coroutine failed.
    #[error(transparent)]
    ScriptPut(#[from] ManagesieveScriptPutError),
    /// The CHECKSCRIPT coroutine failed.
    #[error(transparent)]
    ScriptCheck(#[from] ManagesieveScriptCheckError),
    /// The SETACTIVE coroutine failed.
    #[error(transparent)]
    ScriptActivate(#[from] ManagesieveScriptActivateError),
    /// The DELETESCRIPT coroutine failed.
    #[error(transparent)]
    ScriptDelete(#[from] ManagesieveScriptDeleteError),
    /// The RENAMESCRIPT coroutine failed.
    #[error(transparent)]
    ScriptRename(#[from] ManagesieveScriptRenameError),
    /// The raw passthrough coroutine failed.
    #[error(transparent)]
    Raw(#[from] ManagesieveRawError),
    /// The session-opening coroutine failed.
    #[error(transparent)]
    SessionOpen(#[from] ManagesieveSessionOpenError),
    /// Reading from or writing to the stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Opening the TCP connection or negotiating TLS failed.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),
    /// The implementor's own transport failed.
    ///
    /// [`ManagesieveClientStd`] reports I/O through [`Self::Io`]; this
    /// variant exists for implementors whose failures are something
    /// else, such as a JNI upcall or a runtime-specific socket error.
    #[error(transparent)]
    Transport(Box<dyn core::error::Error + Send + Sync>),
}

/// Emits the [`ManagesieveClient`] and [`ManagesieveClientAsync`]
/// command surfaces from a single list of delegations.
///
/// Both traits carry the same one-line bodies, differing only in
/// whether they hand back a value or a future. Writing them twice is
/// how two implementations of one thing drift apart, so the list is
/// written once and expanded twice.
macro_rules! managesieve_client_commands {
    (
        $(
            $(#[$meta:meta])*
            fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $out:ty {
                $coroutine:expr
            }
        )*
    ) => {
        /// Blocking ManageSieve command surface: implement [`run`] and
        /// inherit every command.
        ///
        /// [`ManagesieveClientStd`] implements it over a `Read + Write`
        /// stream; a caller whose transport is its own (a JNI upcall
        /// bridge, a pre-authenticated proxy socket, an in-memory test
        /// double) implements the same one method and gets the rest.
        ///
        /// The `Yield = ManagesieveYield` bound on [`run`] is
        /// deliberate: it admits exactly the coroutines every client
        /// wraps identically. The session opener declares a yield
        /// vocabulary of its own, so it is wired per implementation
        /// rather than defaulted here.
        ///
        /// The trait is not dyn-compatible, because [`run`] is generic.
        /// The dynamism this crate needs lives one layer down, at
        /// [`ManagesieveStream`], which already spans TCP, TLS, unix
        /// sockets and foreign bridges behind a single concrete client
        /// type.
        ///
        /// [`run`]: Self::run
        pub trait ManagesieveClient {
            /// Runs a standard-shape coroutine to completion, fulfilling
            /// its read and write requests against the transport.
            fn run<C, T, E>(&mut self, coroutine: C) -> Result<T, ManagesieveClientError>
            where
                C: ManagesieveCoroutine<Yield = ManagesieveYield, Return = Result<T, E>>,
                ManagesieveClientError: From<E>;

            $(
                $(#[$meta])*
                fn $name(&mut self, $($arg: $ty),*) -> Result<$out, ManagesieveClientError> {
                    self.run($coroutine)
                }
            )*
        }

        /// Async ManageSieve command surface, the
        /// [`ManagesieveClient`] twin for callers whose transport is a
        /// future.
        ///
        /// Everything [`ManagesieveClient`] documents applies here, plus
        /// the `Send` bounds. They are load-bearing rather than
        /// defensive: a plain `async fn` in a trait cannot promise that
        /// the future it returns is `Send`, so anything built from the
        /// default bodies would fail to compile under `tokio::spawn`,
        /// which is the first thing a worker-spawning consumer reaches
        /// for. Declaring the return type explicitly as
        /// `impl Future<..> + Send`, with `Send` as a supertrait so
        /// `&mut Self` carries through, keeps the defaults spawnable.
        ///
        /// [`ManagesieveClient`] deliberately carries no such bound. A
        /// blocking call returns a value, so there is no future whose
        /// auto-traits need pinning down, and requiring `Send` there
        /// would exclude a perfectly good client built on a
        /// thread-affine handle.
        pub trait ManagesieveClientAsync: Send {
            /// Runs a standard-shape coroutine to completion, fulfilling
            /// its read and write requests against the transport.
            fn run<C, T, E>(
                &mut self,
                coroutine: C,
            ) -> impl Future<Output = Result<T, ManagesieveClientError>> + Send
            where
                C: ManagesieveCoroutine<Yield = ManagesieveYield, Return = Result<T, E>> + Send,
                T: Send,
                E: Send,
                ManagesieveClientError: From<E>;

            $(
                $(#[$meta])*
                fn $name(
                    &mut self,
                    $($arg: $ty),*
                ) -> impl Future<Output = Result<$out, ManagesieveClientError>> + Send {
                    self.run($coroutine)
                }
            )*
        }
    };
}

managesieve_client_commands! {
    /// Reads the capabilities a server sends unprompted. Call it once
    /// on a freshly opened connection, and again after a TLS upgrade.
    fn greeting() -> ManagesieveCapabilities {
        ManagesieveGreetingGet::new()
    }

    /// `CAPABILITY` (RFC 5804 §2.4), asking for the current set.
    fn capability() -> ManagesieveCapabilities {
        ManagesieveCapabilityGet::new()
    }

    /// `STARTTLS` (RFC 5804 §2.2).
    ///
    /// On success the caller upgrades the underlying socket to TLS,
    /// builds a new client around the upgraded stream and calls
    /// [`greeting`](Self::greeting) again, since the server re-issues
    /// its capabilities and the cleartext ones are not to be trusted.
    fn starttls() -> () {
        ManagesieveStartTls::new()
    }

    /// `AUTHENTICATE` (RFC 5804 §2.1), running any mechanism io-sasl
    /// computes.
    ///
    /// Returns the capabilities read back afterwards when
    /// `opts.ensure_capabilities` asked for them, and an empty set
    /// otherwise.
    fn authenticate(
        sasl: Sasl,
        opts: ManagesieveAuthenticateOptions,
    ) -> ManagesieveCapabilities {
        ManagesieveAuthenticate::new(sasl, opts)
    }

    /// `LOGOUT` (RFC 5804 §2.3).
    fn logout() -> () {
        ManagesieveLogout::new()
    }

    /// `NOOP` (RFC 5804 §2.13), returning the tag the server echoed.
    fn noop(tag: Option<String>) -> Option<String> {
        ManagesieveNoop::new(tag)
    }

    /// `UNAUTHENTICATE` (RFC 5804 §2.14.1).
    fn unauthenticate() -> () {
        ManagesieveUnauthenticate::new()
    }

    /// `HAVESPACE` (RFC 5804 §2.5), asking whether a script would fit.
    fn have_space(name: String, size: u32) -> () {
        ManagesieveHaveSpace::new(name, size)
    }

    /// `LISTSCRIPTS` (RFC 5804 §2.7).
    fn list_scripts() -> Vec<ManagesieveScript> {
        ManagesieveScriptList::new()
    }

    /// `GETSCRIPT` (RFC 5804 §2.9), returning the script bytes.
    fn get_script(name: String) -> Vec<u8> {
        ManagesieveScriptGet::new(name)
    }

    /// `PUTSCRIPT` (RFC 5804 §2.6), returning the warning text the
    /// server attached to an accepted script, if any.
    fn put_script(name: String, script: Vec<u8>) -> Option<String> {
        ManagesieveScriptPut::new(name, script)
    }

    /// `CHECKSCRIPT` (RFC 5804 §2.12), returning the warning text the
    /// server attached to a valid script, if any.
    fn check_script(script: Vec<u8>) -> Option<String> {
        ManagesieveScriptCheck::new(script)
    }

    /// `SETACTIVE` (RFC 5804 §2.8), [`None`] deactivating whichever
    /// script is active.
    fn activate_script(name: Option<String>) -> () {
        ManagesieveScriptActivate::new(name)
    }

    /// `DELETESCRIPT` (RFC 5804 §2.10).
    fn delete_script(name: String) -> () {
        ManagesieveScriptDelete::new(name)
    }

    /// `RENAMESCRIPT` (RFC 5804 §2.11).
    fn rename_script(name: String, new_name: String) -> () {
        ManagesieveScriptRename::new(name, new_name)
    }

    /// Sends an arbitrary command and returns its response verbatim,
    /// rejections included.
    ///
    /// The CRLF is added when the caller left it out. A command
    /// carrying a literal is passed whole, marker and octets together.
    fn raw(command: Vec<u8>) -> ManagesieveResponse {
        ManagesieveRaw::new(command)
    }
}

const READ_BUFFER_SIZE: usize = 16 * 1024;

// NOTE: both are protocol constants rather than client state, so they
// live next to the scheme table in the session module and stay reachable
// without the client feature. Re-exported here because config layers
// already reach for them through this path.
pub use crate::session::{default_alpn, default_port};

/// Std-blocking ManageSieve client wrapping a single boxed stream.
pub struct ManagesieveClientStd {
    /// The wrapped stream every coroutine is pumped against.
    pub stream: Box<dyn ManagesieveStream>,
}

impl ManagesieveClient for ManagesieveClientStd {
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, ManagesieveClientError>
    where
        C: ManagesieveCoroutine<Yield = ManagesieveYield, Return = Result<T, E>>,
        ManagesieveClientError: From<E>,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                ManagesieveCoroutineState::Complete(Ok(out)) => return Ok(out),
                ManagesieveCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
                    let count = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..count]);
                }
                ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
            }
        }
    }
}

impl ManagesieveClientStd {
    /// Builds a client around `stream`. The caller is responsible for
    /// opening the connection (TCP, TLS handshake if needed, STARTTLS
    /// upgrade if needed).
    pub fn new<S: Read + Write + Send + 'static>(stream: S) -> Self {
        Self {
            stream: Box::new(stream),
        }
    }

    /// Default ALPN protocol identifiers offered during the TLS
    /// handshake, which is an empty list: ManageSieve registers none.
    ///
    /// Delegates to [`session::default_alpn`], where the protocol
    /// constants live; a caller without the client feature reaches them
    /// there.
    ///
    /// [`session::default_alpn`]: crate::session::default_alpn
    pub fn default_alpn() -> Vec<String> {
        default_alpn()
    }

    /// The default ManageSieve port, 4190 whatever the scheme.
    ///
    /// Delegates to [`session::default_port`], where the scheme table
    /// lives.
    ///
    /// [`session::default_port`]: crate::session::default_port
    pub fn default_port(scheme: &str) -> u16 {
        default_port(scheme)
    }

    /// Replaces the underlying stream; useful after a caller-managed
    /// TLS upgrade or reconnection.
    pub fn set_stream<S: Read + Write + Send + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }
}

impl fmt::Debug for ManagesieveClientStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagesieveClientStd")
            .finish_non_exhaustive()
    }
}

/// Marker for everything the client can run against; auto-implemented
/// for any blocking `Read + Write + Send + 'static` impl.
///
/// The `Send` supertrait flows the auto-trait through the `Box<dyn
/// ManagesieveStream>` type erasure so [`ManagesieveClientStd`] can
/// travel between threads. [`as_any_mut`] lets specialized callers
/// downcast the boxed stream back to its concrete type.
///
/// [`as_any_mut`]: ManagesieveStream::as_any_mut
pub trait ManagesieveStream: Read + Write + Send + Any {
    /// Downcasts the boxed stream back to its concrete type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Read + Write + Send + Any> ManagesieveStream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
