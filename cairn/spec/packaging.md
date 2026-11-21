---
cairn: spec
capability: packaging
status: current
---

# Packaging

### Requirement: no_std
`#![no_std]` SHALL be unconditional and `extern crate alloc` SHALL be declared. `extern crate std` SHALL sit behind the `std` feature and nowhere else.

### Requirement: Feature layers
The features SHALL follow the family layering (GUIDELINES.md cargo-006). `client`, on by default, SHALL gate the client side of the protocol: `coroutine`, `send`, `session` and every command module of `rfc5804` but `response`, with the deps only they need (`base64`, `io-sasl` and its client side, `log`, `secrecy`). Without it only the response vocabulary SHALL compile: `rfc5804::response` and the lexer it reads with. `std` SHALL gate the std-blocking client and imply `client`. Each TLS feature (`rustls-ring`, `rustls-aws`, `native-tls`) SHALL imply `std` and `url`, select the pimalaya-stream provider and pull `anyhow` and `rand`, the connect they gate being the only code drawing a SCRAM client nonce. `vendored` SHALL forward to the weak pimalaya-stream dependency. A feature SHALL exist only where it changes the crate set, `client` being the blessed exception.

### Requirement: SASL features
`scram` SHALL imply `client`, pull the crypto crates the exchange needs and SHALL NOT pull `rand`, the coroutines taking the client nonce with the credentials, so that the coroutine layer with `scram` builds without std. It SHALL enable both io-sasl SCRAM features: RFC 5804 section 2.1 tells client implementations to implement SCRAM-SHA-1, so a default build carrying only the SHA-2 profiles would not conform.

`cram-md5` SHALL imply `client` and stay off, a weak mechanism reaching a build only by request. The io-sasl dependency SHALL name no preparation feature: io-sasl prepares the credentials of PLAIN and SCRAM in every build, which is what RFC 5804 section 2.1 requires of a client.

### Requirement: Dependencies
The vocabulary SHALL depend only on `thiserror`, and the coroutine layer only on `base64`, `io-sasl`, `log`, `secrecy` and `thiserror`. `anyhow`, `base64`, `io-sasl`, `log`, `pimalaya-stream`, `rand`, `secrecy` and `url` SHALL be optional and pulled by the features needing them. A TLS implementation SHALL NOT be a direct dependency.

### Requirement: Layout
The source tree SHALL mirror the specification: `rfc5804` holds the whole protocol, one module per command plus `response` and `capability`. Code spanning the commands SHALL live at the crate root: `coroutine`, `send`, `session`, `client` and the private `utils`.
