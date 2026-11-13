---
cairn: delta
change: authenticate-and-session-fixes
---

## ADDED Requirements

### Requirement: Credentials in memory
`ManagesieveAuthenticateCommand` SHALL hold its initial response as a `SecretBox<[u8]>`, and the coroutine SHALL hold a mechanism payload awaiting its challenge the same way, so that neither prints through `Debug` and both are zeroised when dropped. The bytes handed to the caller in `WantsWrite` are the caller's.

### Requirement: Terminal state
Once it completed, with a success or with an error, the coroutine SHALL answer every further resume with `ManagesieveAuthenticateError::Completed`. It SHALL NOT panic, whatever the order a caller resumes it in.

### Requirement: Argument hand-off
A coroutine running several steps in one loop SHALL hand a resume argument to one step only, taking it out of the option as it does (`arg.take()`), so that the bytes completing one step never reach the next.

### Requirement: URL host
`ManagesieveSessionTransport::from_url` SHALL hand the host over as a connect call takes it: an IPv6 address without the brackets a URL writes around it, an IPv4 address and a domain as they are.

## MODIFIED Requirements

### Requirement: Feature layers
`client` SHALL gate the std-blocking client. Each TLS feature (`rustls-ring`, `rustls-aws`, `native-tls`) SHALL imply `client` and `url`, select the pimalaya-stream provider and pull `anyhow` and `rand`, the connect they gate being the only code drawing a SCRAM client nonce. `vendored` SHALL forward to pimalaya-stream. A feature SHALL exist only where it changes the crate set, `client` being the blessed exception.

### Requirement: SASL features
`scram` SHALL pull the crypto crates the exchange needs and SHALL NOT pull `rand`, the coroutines taking the client nonce with the credentials, so that the coroutine layer with `scram` builds without std. It SHALL enable both io-sasl SCRAM features: RFC 5804 section 2.1 tells client implementations to implement SCRAM-SHA-1, so a default build carrying only the SHA-2 profiles would not conform.

`cram-md5` SHALL stay off, a weak mechanism reaching a build only by request. SASLprep SHALL be enabled on the io-sasl dependency rather than left to its default set, RFC 5804 section 2.1 requiring the authorization identity to be prepared.

### Requirement: State naming
A coroutine's private `State` enum SHALL name each variant after the action in flight, as a present-tense verb (`Start`, `Write`, `Read`, `Cancel`). An `Await` or `Pending` prefix is banned. Each SHALL carry a `Display` impl reading the same way (`send putscript`, `read challenge`), and a state change SHALL be logged with `debug!("{}", self.state)`. A terminal `Done` state, where a coroutine has one, is the exception to the verb.
