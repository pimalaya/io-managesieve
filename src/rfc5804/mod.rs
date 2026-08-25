//! RFC 5804: a protocol for remotely managing Sieve scripts.
//!
//! One module per command, each pairing a command type serialisable to
//! wire bytes with the I/O-free coroutine running its exchange, next to
//! the two modules the commands share: [`response`] for the framing
//! every answer arrives in, and [`capability`] for the set a server
//! advertises.
//!
//! The specification is a single RFC, so this is the only RFC module
//! the crate has; what spans it lives at the crate root.

pub mod authenticate;
pub mod capability;
pub mod checkscript;
pub mod deletescript;
pub mod getscript;
pub mod greeting;
pub mod havespace;
pub mod listscripts;
pub mod logout;
pub mod noop;
pub mod putscript;
pub mod raw;
pub mod renamescript;
pub mod response;
pub mod setactive;
pub mod starttls;
pub mod unauthenticate;
