---
cairn: change
id: authenticate-and-session-fixes
status: landed
created: 2026-11-13
---

# Five loose ends in the authentication exchange, the session opener and the manifest

The family audit of 2026-11-13 left five findings on this crate that are small on their own and share nothing but their size. They land together. Each is described on its own terms below, with the audit id it answers.

## The command prints its credentials (SIEVE-03)

`ManagesieveAuthenticateCommand` carried its initial response as a `Vec<u8>` and derived `Debug`. For PLAIN that response is the authorization identity, the user and the password, so a caller logging the command with `{:?}` printed the password as a list of bytes. The coroutine kept the same payload in a plain `Vec<u8>` while it waited for the empty challenge.

Both become `SecretBox<[u8]>`: redacted by `Debug`, zeroised on drop. The command loses `Eq` and `PartialEq`, which a secret does not offer. The framed bytes a `WantsWrite` hands over stay a `Vec<u8>`: that is the yield every command shares, and what is written belongs to the caller.

## A second resume panics (SIEVE-04)

The coroutine kept its credentials and its cancellation cause in options it took once and `expect`ed. A caller resuming it after it had completed with an error, a retry loop or a generic pump with a bug, reached one of the two: `credentials taken twice` after an unsupported mechanism, `cancellation cause taken twice` after a cancelled exchange. A panic in a no_std library is not an answer to a caller error.

The state machine now takes its state by value at each step and leaves `Done` behind, so a step that completes, with a success or an error, has nothing left to resume, and a step that goes on says where to. The credentials live in `Start`, the cause in `Cancel` and `Abort`; no option is left to take twice. `Done` answers `ManagesieveAuthenticateError::Completed`.

The capability refresh is the one step this costs something: `managesieve_try!` returns on a yield without a chance to put the state back, so that arm matches the sub-coroutine by hand.

## `scram` pulls std into the coroutines (SIEVE-02)

The `scram` feature enabled `rand` with its default features, std among them, although the only code drawing a nonce is the std client's `connect`, compiled under a TLS feature. The coroutines take the nonce with the credentials. A build of the coroutines with SCRAM therefore depended on std for nothing, against the packaging spec's own "the coroutine layer SHALL depend only on" list.

`rand` moves from `scram` to the three TLS features, declared with `default-features = false` and `thread_rng`, the one feature `connect` uses. The price is a TLS build without `scram` compiling `rand` unused, Cargo having no way to enable a dependency on two features at once.

## A step is handed the previous step's bytes (SMTP-09, this crate's half)

`ManagesieveSessionOpen` passed its resume argument to `managesieve_try!` without taking it, so the bytes that completed the greeting reached the next step in the same call. Nothing went wrong, because every step that follows another writes before it reads. It is a trap for the day one does not. The argument is taken at each hand-off, as io-imap does.

## An IPv6 host keeps its brackets (SMTP-10, this crate's half)

`from_url` took the host from `Url::host_str`, which writes an IPv6 address between brackets. The connect request then carried `[2001:db8::25]`, which a resolver reads as a name. The host is now matched on `Url::host` and an IPv6 address rendered bare.

A non-ASCII host is a separate question and is left open: these schemes are not special to the url crate, which percent-encodes such a host rather than converting it to punycode. Doing it right takes an IDNA dependency or a helper shared across the family.

## Also

The test modules imported `coroutine::*` next to a glob that already brings it, which the current toolchain reports as an unused import and `-D warnings` turns into an error. The seventeen imports are gone.

The move from the base64 crate to base64-codec was considered and not done here. base64-codec decodes leniently, blanks and missing padding included, where RFC 4648 section 3.3 tells a decoder to reject characters outside the alphabet unless the referring specification says otherwise, and RFC 5804 section 2.1 was not found to (read from memory of the text, not against a fetched copy). It also needs Rust 1.89 where this crate declares 1.88. Both are the maintainer's to decide.
