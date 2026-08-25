//! Generator-shape coroutine contract. Mirrors `core::ops::Coroutine`:
//! `Yield` for intermediate progress, `Return` for terminal output,
//! [`ManagesieveCoroutineState`] for both.

use alloc::vec::Vec;

/// State yielded by a [`ManagesieveCoroutine::resume`] step.
#[derive(Debug)]
pub enum ManagesieveCoroutineState<Y, R> {
    /// Intermediate yield; the caller reacts and resumes.
    Yielded(Y),
    /// Terminal yield; by convention `R = Result<Output, Error>`.
    Complete(R),
}

/// Standard-shape ManageSieve coroutine.
pub trait ManagesieveCoroutine {
    /// Per-step value.
    type Yield;
    /// Terminal value; by convention `Result<Output, Error>`.
    type Return;

    /// Advances the coroutine one step. Pass `None` for the initial
    /// call or after a [`ManagesieveYield::WantsWrite`]; `Some(data)`
    /// after a [`ManagesieveYield::WantsRead`]; `Some(&[])` to signal
    /// EOF.
    fn resume(
        &mut self,
        arg: Option<&[u8]>,
    ) -> ManagesieveCoroutineState<Self::Yield, Self::Return>;
}

/// Standard I/O-only Yield; every command coroutine in this crate picks
/// it.
///
/// The two coroutines declaring a vocabulary of their own are the
/// session opener, which also asks for sockets, and nothing else.
#[derive(Debug)]
pub enum ManagesieveYield {
    /// The caller should read more bytes and feed them back on resume.
    WantsRead,
    /// The caller should write these bytes; the next resume takes
    /// `None`.
    WantsWrite(Vec<u8>),
}

/// Coroutine `?`: forwards `Yielded` (via `Into`), short-circuits on
/// `Err`, evaluates to the inner `Ok` value.
#[macro_export]
macro_rules! managesieve_try {
    ($coroutine:expr, $arg:expr $(,)?) => {
        match $crate::coroutine::ManagesieveCoroutine::resume($coroutine, $arg) {
            $crate::coroutine::ManagesieveCoroutineState::Yielded(y) => {
                return $crate::coroutine::ManagesieveCoroutineState::Yielded(y.into());
            }
            $crate::coroutine::ManagesieveCoroutineState::Complete(Err(err)) => {
                return $crate::coroutine::ManagesieveCoroutineState::Complete(Err(err.into()));
            }
            $crate::coroutine::ManagesieveCoroutineState::Complete(Ok(value)) => value,
        }
    };
}
