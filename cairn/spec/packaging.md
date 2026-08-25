---
cairn: spec
capability: packaging
status: current
---

# Packaging

### Requirement: no_std
`#![no_std]` SHALL be unconditional and `extern crate alloc` SHALL be declared. `extern crate std` SHALL sit behind the `client` feature and nowhere else.

### Requirement: Feature layers
`client` SHALL gate the std-blocking client. Each TLS feature (`rustls-ring`, `rustls-aws`, `native-tls`) SHALL imply `client` and `url`, select the pimalaya-stream provider and pull `anyhow`. `vendored` SHALL forward to pimalaya-stream. A feature SHALL exist only where it changes the crate set, `client` being the blessed exception.

### Requirement: SASL features
`scram` SHALL pull the crypto crates the exchange needs plus `rand` for the nonce the std client draws, and SHALL enable both io-sasl SCRAM features: RFC 5804 section 2.1 tells client implementations to implement SCRAM-SHA-1, so a default build carrying only the SHA-2 profiles would not conform.

`cram-md5` SHALL stay off, a weak mechanism reaching a build only by request. SASLprep SHALL be enabled on the io-sasl dependency rather than left to its default set, RFC 5804 section 2.1 requiring the authorization identity to be prepared.

### Requirement: Dependencies
The coroutine layer SHALL depend only on `base64`, `io-sasl`, `log`, `secrecy` and `thiserror`. `anyhow`, `pimalaya-stream`, `rand` and `url` SHALL be optional and pulled by the features needing them. A TLS implementation SHALL NOT be a direct dependency.

### Requirement: Layout
The source tree SHALL mirror the specification: `rfc5804` holds the whole protocol, one module per command plus `response` and `capability`. Code spanning the commands SHALL live at the crate root: `coroutine`, `send`, `session`, `client` and the private `utils`.
