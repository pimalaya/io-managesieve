---
cairn: log
change: authenticate-and-session-fixes
landed: 2026-11-13
---

# Authentication and session fixes

Five findings of the family audit of 2026-11-13, small and unrelated, plus the lint the toolchain bump turned into an error.

**Credentials out of `Debug`** (SIEVE-03). `ManagesieveAuthenticateCommand::initial_response` is an `Option<SecretBox<[u8]>>`, and so is the payload `ManagesieveAuthenticate` holds until the empty challenge arrives: every payload is wrapped as it leaves the mechanism. Before, the `Debug` of a PLAIN command read `initial_response: Some([0, 97, 108, 105, 99, 101, 0, 115, 101, 99, 114, 101, 116])`. The command no longer derives `Eq` and `PartialEq`. The bytes a `WantsWrite` carries stay a plain `Vec<u8>`.

**No panic on a second resume** (SIEVE-04). `ManagesieveAuthenticate::resume` takes its state by value and leaves `State::Done`, so completing is terminal by construction and the two options the old code `expect`ed (`credentials taken twice`, `cancellation cause taken twice`) are gone: the credentials travel in `State::Start`, the cancellation cause in `State::Cancel` and `State::Abort`. A resume in `Done` answers the new `ManagesieveAuthenticateError::Completed`. The capability refresh matches its sub-coroutine by hand, `managesieve_try!` leaving no room to put the state back on a yield.

**`scram` without `rand`** (SIEVE-02). `dep:rand` left `scram` for `rustls-ring`, `rustls-aws` and `native-tls`, and is declared with `default-features = false, features = ["thread_rng"]`. `cargo tree --no-default-features --features scram -e features` listed `rand` with `default`, `std`, `std_rng`, `sys_rng` and `thread_rng`, plus getrandom; it now lists neither crate. A TLS build without `scram` compiles `rand` unused.

**One step per argument** (SMTP-09, this crate's half). The four steps of `ManagesieveSessionOpen` and the capability refresh of the authentication exchange take the resume argument as they hand it on. No behaviour moved and no test could fail before: every step that follows another writes first.

**IPv6 URL hosts** (SMTP-10, this crate's half). `ManagesieveSessionTransport::from_url` matches on `Url::host`, so `sieves://[2001:db8::25]:5190` gives the host `2001:db8::25` where it gave `[2001:db8::25]`. A non-ASCII host is still handed over percent-encoded.

**Lint.** Seventeen test modules imported `coroutine::*` beside a glob already bringing it; rustc 1.99.1 reports that, and `cargo clippy --all-features --all-targets -- -D warnings` failed on it. It passes, with no default features, `client` alone, `url` alone, the default set and all features.

**Breaking**: the type of `ManagesieveAuthenticateCommand::initial_response`, the `Eq` and `PartialEq` it no longer derives, the new `ManagesieveAuthenticateError::Completed` variant, and `scram` no longer enabling `rand`.

**Not done.** The swap from the base64 crate to base64-codec: its decoder accepts blanks, missing padding and trailing bits that the strict decoder in place refuses, and it needs Rust 1.89 against the 1.88 declared here. Punycode for a non-ASCII URL host: it takes an IDNA dependency or a family helper.

Verified: 113 unit tests, 13 integration tests and 17 doctests green with every feature, the suite green in the four other feature shapes, and the `read` fuzz target clean over 267,345 runs in 41 seconds against the reworked exchange.

Spec updated: `authentication` (ADDED: "Credentials in memory", "Terminal state"), `coroutines` (ADDED: "Argument hand-off"; MODIFIED: "State naming"), `session` (ADDED: "URL host"), `packaging` (MODIFIED: "Feature layers", "SASL features").
