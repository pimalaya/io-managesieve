#![no_std]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # io-managesieve
//!
//! I/O-free ManageSieve client coroutines: every network exchange is a
//! resumable state machine emitting read and write requests instead of
//! performing I/O itself, so the caller owns the socket and pumps the
//! coroutine (see the std feature for a ready-made std-blocking
//! pump).
//!
//! ManageSieve ([RFC 5804]) is how a user edits the Sieve scripts a
//! sealed mail server runs on their behalf: list them, download one,
//! upload a new one and have the server compile it, then choose which
//! one filters incoming mail. This crate speaks that protocol and
//! nothing else. It parses no Sieve, the server being what compiles a
//! script and reports where it went wrong.
//!
//! ## Features
//!
//! The response vocabulary ([`rfc5804::response`]) is always compiled.
//! `client`, on by default, adds the coroutines, the session and the
//! command modules, with base64, io-sasl, log and secrecy; `scram` and
//! `cram-md5` add their SASL mechanisms to it, and `url` the session's
//! URL reading. `std` adds the blocking client, and each TLS feature
//! (`rustls-ring` by default, `rustls-aws`, `native-tls`) its connector.
//!
//! ## The coroutine contract
//!
//! Every coroutine implements [`coroutine::ManagesieveCoroutine`],
//! whose resume method takes an optional byte slice and yields a
//! [`coroutine::ManagesieveCoroutineState`]: either an intermediate
//! [`coroutine::ManagesieveYield`] asking the caller to read bytes from
//! the stream (fed back on the next resume, an empty slice signalling
//! EOF) or to write the yielded bytes, or a terminal value carrying the
//! result. Each module ships a runnable example of the pump loop, and
//! [`client::ManagesieveClientStd`] implements it once for blocking std
//! streams.
//!
//! Most coroutines delegate their wire exchange to
//! [`send::ManagesieveCommandSend`], the base coroutine owning the
//! serialise, write, read and parse cycle; they only interpret the
//! response. The exceptions are the pure read coroutines (the greeting
//! and the capability refresh following a TLS upgrade), which own no
//! write because nothing is sent first, and the authentication
//! exchange, which reads a line at a time because it has to answer each
//! challenge before the response is over.
//!
//! ## Layout: one folder for one RFC
//!
//! ManageSieve is a single specification, so [`rfc5804`] holds the
//! whole protocol, one module per command: the greeting, CAPABILITY,
//! STARTTLS, AUTHENTICATE, LOGOUT, NOOP, UNAUTHENTICATE, HAVESPACE,
//! LISTSCRIPTS, GETSCRIPT, PUTSCRIPT, CHECKSCRIPT, SETACTIVE,
//! DELETESCRIPT, RENAMESCRIPT and a raw passthrough. Two modules there
//! carry what the commands share:
//! [`rfc5804::response`] the framing every answer arrives in, and
//! [`rfc5804::capability`] the set a server advertises.
//!
//! Code spanning the commands lives at the crate root: [`coroutine`]
//! defines the coroutine contract and the managesieve_try macro,
//! [`send`] the base read and send coroutines, [`session`] the
//! composite session-opening coroutine, the private utils module the
//! ACAP-style lexer and quoting the protocol borrows, and [`client`]
//! the optional std-blocking client (std feature) exposing one
//! method per coroutine plus, with a TLS feature enabled, an end-to-end
//! connect covering transport, STARTTLS and SASL.
//!
//! ## One coroutine for every mechanism
//!
//! [`rfc5804::authenticate`] frames every SASL mechanism io-sasl
//! computes, where io-imap and io-smtp carry a module per mechanism.
//! Those two frame each one differently; ManageSieve frames them all
//! the same way, a mechanism name and a base64 string each way, so the
//! mechanism is a value here rather than a module. Server-first
//! mechanisms come free of that, CRAM-MD5 being the one that needs it.
//! The two Kerberos relays are refused by name, their exchange needing
//! a yield vocabulary this crate does not have.
//!
//! ## Opening a session
//!
//! [`session`] provides
//! [`session::ManagesieveSessionOpen`], the composite coroutine
//! covering everything between an address and an authenticated session:
//! transport selection, the greeting, the optional STARTTLS upgrade
//! with a second capability read over TLS, and the SASL exchange. It
//! yields transport requests (connect this socket, upgrade that one)
//! alongside the usual reads and writes, so a caller on any runtime
//! answers them with its own sockets and inherits the ordering. The std
//! client is a thirty-line pump over it.
//!
//! By default the session refuses to send a password or a bearer token
//! over a cleartext connection, which is the configuration RFC 5804
//! section 5 asks implementations to carry.
//!
//! ## Conventions
//!
//! The crate is unconditionally no_std; alloc is always required, std
//! only under the std feature. Public items carry the bare
//! Managesieve domain prefix (the protocol is not versioned, its
//! VERSION capability naming the specification rather than a wire
//! format). Coroutine errors normalise to the shape "ManageSieve
//! COMMAND failed: cause", and RFC wire tokens (mechanism names,
//! capability names, response codes) keep their exact spelling.
//!
//! [RFC 5804]: https://www.rfc-editor.org/rfc/rfc5804

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod client;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod coroutine;
pub mod rfc5804;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod send;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod session;
pub(crate) mod utils;
