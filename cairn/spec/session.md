---
cairn: spec
capability: session
status: current
---

# Session

Everything between a bare address and an authenticated session is one composite coroutine, so the ordering and the policy stay reachable from any runtime rather than living inside the std client.

### Requirement: Composite session opener
`session::ManagesieveSessionOpen` SHALL cover transport selection, the greeting, the optional STARTTLS upgrade with a second capability read over TLS, and the SASL exchange. It SHALL yield `ManagesieveSessionOpenYield`, adding `WantsTcpConnect`, `WantsTlsConnect`, `WantsUnixConnect` and `WantsTlsUpgrade` to the standard read and write. A caller that skips a step cannot advance, the state machine never asking for the next one.

### Requirement: Scheme table
`sieve://` SHALL be plain TCP, `sieves://` implicit TLS and `unix://` a local socket, all defaulting to port 4190, the only port RFC 5804 registers. `sieves` is this project's name for the deployments listening for a TLS handshake straight away, which the specification does not define, and SHALL be documented as such.

### Requirement: STARTTLS
STARTTLS on an already-encrypted transport SHALL fail before a socket is opened. STARTTLS against a server not advertising it SHALL fail rather than carrying on in the clear. The capabilities read before the upgrade SHALL be discarded and re-read afterwards.

### Requirement: Cleartext credentials
A mechanism disclosing a reusable credential, meaning PLAIN, LOGIN, OAUTHBEARER and XOAUTH2, SHALL be refused over a cleartext TCP transport unless `allow_cleartext_auth` is set. This is the configuration RFC 5804 section 5 asks implementations to carry. A local socket and an implicit-TLS transport count as protected, and so does a connection after a STARTTLS upgrade.

### Requirement: No pre-authenticated greeting
Authentication SHALL be skipped only when no mechanism is given, ManageSieve having no PREAUTH greeting. That is what a local socket reaching an already-authenticated proxy wants.

### Requirement: Protocol constants
`default_port` SHALL answer 4190 whatever the scheme, and `default_alpn` SHALL answer an empty list, no ALPN identifier being registered for ManageSieve. Both SHALL stay reachable without the client feature, config layers being what read them.
