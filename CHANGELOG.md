# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-13

### Added

- Added the `parse` and `read` fuzz targets, run from the `fuzz` devShell.

- Added `ManagesieveAuthenticateError::Completed`, what `ManagesieveAuthenticate` answers when resumed after it completed.

  **BREAKING** for a match naming every variant.

- Added the `scram` field to `ManagesieveAuthenticateOptions` and `ManagesieveSessionOpenOptions`, behind the `scram` feature.

  An io-sasl `SaslScramOptions` bounding the iteration count a SCRAM server may announce, 4096 to five million by default. **BREAKING** for a literal naming every field.

### Changed

- **BREAKING**: Changed the io-sasl dependency to 0.2.

  SCRAM refuses an iteration count outside its bounds and a client nonce shorter than 18 bytes, and PLAIN and SCRAM prepare their credentials in every build.

- Changed the minimum Rust version to 1.89, io-sasl's.

- Changed the `scram` feature to pull no randomness: `rand` now comes with the TLS features, whose connect is the only code drawing a nonce.

  A build of the coroutines with `scram` alone no longer depends on `rand` and its `std` feature.

### Fixed

- Fixed `ManagesieveAuthenticate` panicking when resumed after it completed with an error.

- Fixed `ManagesieveSessionTransport::from_url` keeping the brackets around an IPv6 host.

  `sieve://[2001:db8::25]` now asks for a connection to `2001:db8::25`.

### Security

- Fixed `send::ManagesieveResponseRead` and `rfc5804::authenticate::ManagesieveAuthenticate` reading a response again from its first byte at each read.

  Each byte is searched, lexed and copied once, so a response costs what its size costs however a server splits it over the reads.

- Fixed `ManagesieveAuthenticateCommand` showing its initial response through `Debug`.

  **BREAKING**: `initial_response` is an `Option<SecretBox<[u8]>>`, redacted when printed and zeroised when dropped, and the command no longer derives `Eq` and `PartialEq`.

## [0.2.0] - 2026-09-29

### Added

- Added `ManagesieveClientStdConnectOptions`, whose `proxy` field tunnels the connection through a SOCKS5 or HTTP proxy.

### Changed

- **BREAKING**: `ManagesieveClientStd::connect` takes `(url, opts)`, the TLS configuration, the SASL mechanism and the session options moving into `ManagesieveClientStdConnectOptions`.

## [0.1.0] - 2026-08-25

### Added

- Added the `ManagesieveCoroutine` trait, the I/O-free contract every exchange implements.

  A `resume(Option<&[u8]>)` method returning `ManagesieveCoroutineState<Yield, Return>`, where the standard `ManagesieveYield` is either `WantsRead` or `WantsWrite(Vec<u8>)`. The caller owns the socket and pumps the coroutine, so the same state machines run under a blocking, an async or an in-memory driver.

- Added the response framing of RFC 5804, parsed once for every command.

  A logical line spans as many physical ones as it has literals, a `{n}` marker making the CRLF that follows content rather than a line ending. `ManagesieveResponse::parse` answers `None` while a response is incomplete and returns it with the bytes it consumed once it is, since finding the end and reading the tokens are the same walk over the literals.

- Added `ManagesieveResponseCode`, modelling the eleven codes RFC 5804 section 1.3 defines.

  A missing script, a taken name, a quota and a compilation warning each arrive as themselves rather than as text to grep. An unmodelled code keeps its name, and an unknown `QUOTA` detail folds back onto `QUOTA`, as clients are asked to do.

- Added a coroutine for every command the specification defines: the capability greeting, `CAPABILITY`, `STARTTLS`, `AUTHENTICATE`, `LOGOUT`, `NOOP`, `UNAUTHENTICATE`, `HAVESPACE`, `LISTSCRIPTS`, `GETSCRIPT`, `PUTSCRIPT`, `CHECKSCRIPT`, `SETACTIVE`, `DELETESCRIPT` and `RENAMESCRIPT`, plus a raw passthrough for whatever a later extension adds.

- Added `ManagesieveAuthenticate`, one coroutine framing every SASL mechanism io-sasl computes.

  RFC 5804 wraps them all identically, a mechanism name and a base64 string each way, so the mechanism is a value rather than a module: ANONYMOUS, EXTERNAL, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2 and the three SCRAM profiles, with CRAM-MD5 behind its own feature. A server-first mechanism needs no special case, and the two Kerberos relays are refused by name rather than silently skipped.

  A mechanism refusing what the server said cancels the exchange with the `"*"` string of RFC 5804 section 2.1 and reads the reply, so the caller keeps a session it can use rather than a stream out of step with its server.

- Added `ManagesieveSessionOpen`, the composite coroutine covering everything between an address and an authenticated session.

  Transport selection, the greeting, the optional STARTTLS upgrade with a second capability read over TLS, and the SASL exchange. It yields transport requests alongside reads and writes, so a caller on any runtime answers them with its own sockets and inherits the ordering.

- Added the refusal to send a replayable credential over a cleartext connection.

  PLAIN, LOGIN, OAUTHBEARER and XOAUTH2 hand a passive observer something it can reuse, and RFC 5804 section 5 asks implementations to carry a configuration where such mechanisms cannot run without an encryption layer. That configuration is the default here; `allow_cleartext_auth` opts out for a link the caller trusts.

- Added the refusal of bytes arriving past the greeting or past the `STARTTLS` reply.

  Nothing legitimate follows either, and a client is about to open a TLS session those bytes would be replayed inside, so the coroutine fails rather than handing them back for a caller to check or forget.

- Added the std client behind the `client` feature.

  `ManagesieveClient` and `ManagesieveClientAsync` carry one method per coroutine over a single `run`, and `ManagesieveClientStd` implements the blocking one over any `Read + Write` stream. With a TLS feature enabled, `connect` opens a whole authenticated session from a URL, answering the session coroutine's transport requests with a pimalaya-stream `Stream`.

[unreleased]: https://github.com/pimalaya/io-managesieve/compare/v0.3.0..HEAD
[0.3.0]: https://github.com/pimalaya/io-managesieve/compare/v0.1.0..v0.3.0
[0.1.0]: https://github.com/pimalaya/io-managesieve/compare/root..v0.1.0
