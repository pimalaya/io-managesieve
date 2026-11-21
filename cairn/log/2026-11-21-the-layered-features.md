---
cairn: log
change: the-layered-features
landed: 2026-11-21
---

# The layered features

Landed without a proposal (the family's cargo-006 feature shape, the one io-imap, io-smtp and io-webdav ship, applied as a packaging change).

**Features.** The old `client` feature, which gated the blocking client and std, is renamed `std`. `client` now gates the client side of the protocol (`coroutine`, `send`, `session` and every command module of `rfc5804` but `response`) and makes base64, io-sasl, log and secrecy optional; it is on by default and implied by `std`, which the TLS features imply. `scram` and `cram-md5` imply `client`, as io-imap's `scram` does. Without `client` only the response vocabulary compiles: `rfc5804::response` and the lexer of the private utils. The quoting helpers of utils (`quote`, `literal`, `string`, `escape_byte_string`) and `LineBuffer` carry their own `cfg`. `vendored` forwards to the weak pimalaya-stream dependency, as cargo-006 asks. `default_port` and `default_alpn` stay reachable without std, under `client` alone.

**Examples and tests.** std_coroutine requires `client`, std_client_light `std`, tokio_session `client` and `url`. tests/exchange.rs gates on `std` (it drives `ManagesieveClientStd`), tests/drip.rs and tests/mechanisms.rs on `client`. The CI matrix (.github/workflows/tests.yml) runs no features, `client`, `client,url`, `std` and default; `url` alone no longer compiles anything that reads it.

**Fuzz package.** fuzz/Cargo.toml names `client` on the crate, whose targets drive the coroutines, and moves io-sasl from 0.2 to 0.3, the version the crate depends on: with 0.2 the `read` target did not compile (`Sasl: From<SaslPlainCreds>` unsatisfied across the two io-sasl versions). fuzz/Cargo.lock follows (io-managesieve 0.3.0 to 0.5.0, io-sasl 0.3.0 alone). `cargo check` over the fuzz package passes; no fuzz run.

**Verified.** Builds with no features, `client`, `std`, default and all features are warning-free; tests pass with no features, `client`, `client,url`, `std`, default and all features; clippy over all features and all targets, rustdoc with warnings denied and `cargo fmt --check` are clean.

Capabilities moved: packaging ("no_std", "Feature layers", "SASL features", "Dependencies" modified), client (feature name), session ("Protocol constants" modified), testing ("Feature matrix" modified).
