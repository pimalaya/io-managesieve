//! What a response costs when it arrives a few bytes at a time.
//!
//! A peer chooses how its bytes are split over the reads, so the work a
//! response costs has to follow its size rather than the number of
//! reads it took. A clock is nothing a test can assert on, so these
//! count the bytes the coroutines allocate instead: a reader starting
//! over at each read builds its tokens and copies its literals again,
//! and the count shows it.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use io_managesieve::{
    coroutine::{ManagesieveCoroutine, ManagesieveCoroutineState, ManagesieveYield},
    rfc5804::{
        authenticate::{
            ManagesieveAuthenticate, ManagesieveAuthenticateError, ManagesieveAuthenticateOptions,
        },
        listscripts::ManagesieveScriptList,
    },
    send::{ManagesieveCommandSendError, ManagesieveResponseRead},
};
use io_sasl::rfc4616::plain::SaslPlainCreds;

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

#[test]
fn a_dripped_response_costs_in_proportion_to_its_size() {
    let small = listscripts_cost(100);
    let large = listscripts_cost(400);

    assert!(
        large < 6 * small,
        "4 times the response allocated {large} bytes against {small}"
    );
}

#[test]
fn a_dripped_response_copies_a_literal_once() {
    let script = vec![b'#'; 64 * 1024];

    let mut wire = format!("{{{}}}\r\n", script.len()).into_bytes();
    wire.extend_from_slice(&script);
    let head = wire.len();
    wire.extend_from_slice(&[b' '; 256]);
    wire.extend_from_slice(b"\r\nOK\r\n");

    let mut reads = vec![&wire[..head]];
    reads.extend(wire[head..].chunks(1));

    let mut read = ManagesieveResponseRead::new();
    let mut reads = reads.into_iter();
    let mut arg = None;

    let before = ALLOCATED.get();

    let out = loop {
        match read.resume(arg.take()) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
                arg = Some(reads.next().unwrap());
            }
            ManagesieveCoroutineState::Complete(Ok(out)) => break out,
            state => panic!("expected WantsRead or Complete(Ok), got {state:?}"),
        }
    };

    let allocated = ALLOCATED.get() - before;

    assert_eq!(out.response.data[0].string(0).unwrap(), script);
    assert!(
        allocated < 8 * wire.len(),
        "{} bytes on the wire allocated {allocated}",
        wire.len()
    );
}

#[test]
fn a_dripped_challenge_copies_a_literal_once() {
    let challenge = vec![b'A'; 64 * 1024];

    let mut head = format!("{{{}}}\r\n", challenge.len()).into_bytes();
    head.extend_from_slice(&challenge);

    let creds = SaslPlainCreds {
        authzid: None,
        authcid: String::from("alice"),
        passwd: String::from("secret").into(),
    };

    let mut auth = ManagesieveAuthenticate::new(creds, ManagesieveAuthenticateOptions::default());

    assert!(matches!(
        auth.resume(None),
        ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(_))
    ));
    assert!(matches!(
        auth.resume(None),
        ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead)
    ));

    let before = ALLOCATED.get();

    assert!(matches!(
        auth.resume(Some(&head)),
        ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead)
    ));

    for _ in 0..256 {
        assert!(matches!(
            auth.resume(Some(b" ")),
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead)
        ));
    }

    let allocated = ALLOCATED.get() - before;

    assert!(matches!(
        auth.resume(Some(b"")),
        ManagesieveCoroutineState::Complete(Err(ManagesieveAuthenticateError::Send(
            ManagesieveCommandSendError::Eof
        )))
    ));
    assert!(
        allocated < 8 * head.len(),
        "{} bytes on the wire allocated {allocated}",
        head.len()
    );
}

/// The bytes allocated listing `scripts` scripts, one byte per read.
fn listscripts_cost(scripts: usize) -> usize {
    let mut wire = Vec::new();

    for index in 0..scripts {
        wire.extend_from_slice(format!("\"script-{index:06}\"\r\n").as_bytes());
    }

    wire.extend_from_slice(b"OK\r\n");

    let mut list = ManagesieveScriptList::new();
    let mut reads = wire.chunks(1);
    let mut arg = None;

    let before = ALLOCATED.get();

    let found = loop {
        match list.resume(arg.take()) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(_)) => {}
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
                arg = Some(reads.next().unwrap());
            }
            ManagesieveCoroutineState::Complete(Ok(found)) => break found,
            ManagesieveCoroutineState::Complete(Err(err)) => panic!("{err}"),
        }
    };

    let allocated = ALLOCATED.get() - before;

    assert_eq!(found.len(), scripts);
    allocated
}
