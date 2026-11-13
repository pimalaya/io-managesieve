---
cairn: tasks
change: authenticate-and-session-fixes
---

- [x] Remove the seventeen unused `coroutine::*` imports from the test modules, so clippy passes with `-D warnings`
- [x] `ManagesieveAuthenticateCommand::initial_response` and the pending payload as `SecretBox<[u8]>`; drop `Eq` and `PartialEq` from the command (SIEVE-03)
- [x] Take the authentication state by value, leaving `Done`; credentials in `Start`, cause in `Cancel` and `Abort`; `ManagesieveAuthenticateError::Completed` (SIEVE-04)
- [x] Move `dep:rand` from `scram` to the three TLS features, with `default-features = false` and `thread_rng` (SIEVE-02)
- [x] `arg.take()` at every step of `ManagesieveSessionOpen` and at the capability refresh of `ManagesieveAuthenticate` (SMTP-09)
- [x] Render an IPv6 URL host without brackets in `ManagesieveSessionTransport::from_url` (SMTP-10)
- [ ] Convert a non-ASCII URL host to punycode: needs an IDNA dependency or a family helper, left to the maintainer
- [ ] Move from base64 to base64-codec: changes decoding leniency and the minimum Rust version, left to the maintainer
