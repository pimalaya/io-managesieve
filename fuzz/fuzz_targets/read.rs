#![no_main]

//! Coverage-guided fuzz target for the two readers of a response:
//! `ManagesieveResponseRead`, which every command ends on, and the
//! line-at-a-time reader of `ManagesieveAuthenticate`. The same bytes
//! are split into arbitrary reads and followed by EOF, under three
//! oracles.
//!
//! Neither reader panics, nor asks for a read once EOF was reported.
//!
//! The splits change nothing: after each read, `ManagesieveResponseRead`
//! stands where `ManagesieveResponse::parse` stands on the bytes fed so
//! far, waiting, failing or complete alike, down to the trailing bytes.
//!
//! The splits cost nothing: what a reader allocates is bounded by the
//! bytes it was fed, however many reads carried them. A reader starting
//! over at each read builds its tokens again each time, and its count
//! leaves that bound.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use arbitrary::Arbitrary;
use io_managesieve::{
    coroutine::*,
    rfc5804::{authenticate::*, response::*},
    send::*,
};
use io_sasl::rfc4616::plain::SaslPlainCreds;
use libfuzzer_sys::fuzz_target;

/// The bytes a reader may allocate whatever it is fed.
const MAX_ALLOCATED: usize = 4096;

/// The bytes a reader may allocate on top, per byte it is fed.
const MAX_ALLOCATED_PER_BYTE: usize = 512;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

thread_local! {
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, counting the bytes each thread asks it for.
struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.with(|allocated| allocated.set(allocated.get() + layout.size()));

        // SAFETY: the caller upholds the contract of `GlobalAlloc::alloc`
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System` through this allocator
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.with(|allocated| allocated.set(allocated.get() + new_size));

        // SAFETY: `ptr` came from `System` through this allocator
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// What a server sends, and how the transport splits it.
#[derive(Arbitrary, Debug)]
struct Input {
    /// The size of each read less one, cycled over until the wire is
    /// spent. Empty means one byte per read.
    sizes: Vec<u8>,
    wire: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let mut sizes = input
        .sizes
        .iter()
        .map(|size| usize::from(*size) + 1)
        .cycle();
    let mut rest = input.wire.as_slice();
    let mut reads = Vec::new();

    while !rest.is_empty() {
        let size = sizes.next().unwrap_or(1).min(rest.len());
        let (read, tail) = rest.split_at(size);

        reads.push(read);
        rest = tail;
    }

    check_response_read(&reads);
    check_authenticate(&reads);
});

fn check_response_read(reads: &[&[u8]]) {
    let mut read = ManagesieveResponseRead::new();
    let mut reads = reads.iter();
    let mut fed = Vec::new();
    let mut allocated = 0;
    let mut eof = false;
    let mut arg: Option<&[u8]> = None;

    loop {
        let before = ALLOCATED.get();
        let state = read.resume(arg.take());
        allocated += ALLOCATED.get() - before;

        assert!(
            allocated <= MAX_ALLOCATED + MAX_ALLOCATED_PER_BYTE * fed.len(),
            "{} bytes fed allocated {allocated}",
            fed.len()
        );

        let whole = ManagesieveResponse::parse(&fed);

        match state {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(_)) => {
                panic!("a reader writes");
            }
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
                assert!(!eof, "asks for a read after EOF");
                assert_eq!(whole, Ok(None));

                match reads.next() {
                    Some(read) => {
                        fed.extend_from_slice(read);
                        arg = Some(read);
                    }
                    None => {
                        eof = true;
                        arg = Some(b"");
                    }
                }
            }
            ManagesieveCoroutineState::Complete(Ok(out)) => {
                let Ok(Some((response, consumed))) = whole else {
                    panic!("complete where the whole is {whole:?}");
                };

                assert_eq!(out.response, response);
                assert_eq!(out.trailing, fed[consumed..]);
                return;
            }
            ManagesieveCoroutineState::Complete(Err(err)) => {
                match err {
                    ManagesieveCommandSendError::Eof => assert_eq!(whole, Ok(None)),
                    ManagesieveCommandSendError::ParseResponse(err) => assert_eq!(whole, Err(err)),
                    ManagesieveCommandSendError::ResponseTooLarge => {
                        assert!(fed.len() > MAX_RESPONSE);
                    }
                }

                return;
            }
        }
    }
}

fn check_authenticate(reads: &[&[u8]]) {
    let creds = SaslPlainCreds {
        authzid: None,
        authcid: String::from("alice"),
        passwd: String::from("secret").into(),
    };

    let mut auth = ManagesieveAuthenticate::new(creds, ManagesieveAuthenticateOptions::default());
    let mut reads = reads.iter();
    let mut fed = 0;
    let mut allocated = 0;
    let mut eof = false;
    let mut arg: Option<&[u8]> = None;

    loop {
        let before = ALLOCATED.get();
        let state = auth.resume(arg.take());
        allocated += ALLOCATED.get() - before;

        assert!(
            allocated <= MAX_ALLOCATED + MAX_ALLOCATED_PER_BYTE * fed,
            "{fed} bytes fed allocated {allocated}"
        );

        match state {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(_)) => {}
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
                assert!(!eof, "asks for a read after EOF");

                match reads.next() {
                    Some(read) => {
                        fed += read.len();
                        arg = Some(read);
                    }
                    None => {
                        eof = true;
                        arg = Some(b"");
                    }
                }
            }
            ManagesieveCoroutineState::Complete(_) => return,
        }
    }
}
