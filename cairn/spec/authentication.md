---
cairn: spec
capability: authentication
status: current
---

# Authentication

RFC 5804 frames every SASL mechanism identically: a mechanism name and a base64 string out, a base64 string back, until the server answers OK. One coroutine therefore serves them all.

### Requirement: One coroutine per protocol, not per mechanism
`rfc5804::authenticate` SHALL frame every mechanism, dispatching on `io_sasl::mechanism::Sasl` through a private enum. io-imap and io-smtp carry a module per mechanism because their framing differs per mechanism; this crate's does not, so a module per mechanism would be one file repeated.

Adding a mechanism to io-sasl SHALL cost one arm in the dispatch enum, one in its `resume`, and one variant in `ManagesieveAuthenticateError`.

### Requirement: Mechanisms refused by name
A mechanism whose exchange is not the standard challenge-response SHALL be refused as `UnsupportedMechanism`, naming it. The two Kerberos relays are those: what they answer is what the caller's own security context produced rather than what the server sent, which takes a yield vocabulary this coroutine does not have.

### Requirement: Server-first mechanisms
A mechanism answering the first resume with `WantsRead` SHALL send its command bare and feed the server's first challenge back. LOGIN SHALL be treated as server-first whatever the options say, since RFC 5804 section 2.1 tells servers to reject an initial response for a mechanism that speaks second.

### Requirement: Initial response
`initial_response` SHALL inline the mechanism's first payload with the command. Unlike IMAP, no capability gates it: the ManageSieve grammar carries one unconditionally, so the session opener SHALL turn it on.

### Requirement: End of exchange
The final server data MAY arrive in the `SASL` response code of the OK; it SHALL be decoded and fed to the mechanism before the exchange is closed. The mechanism SHALL then be resumed with `SaslArg::Done`, so one performing mutual authentication refuses an exchange that ended before it verified anything.

### Requirement: Cancellation
When a mechanism refuses what the server said, the coroutine SHALL send the `"*"` string RFC 5804 section 2.1 gives clients, read the reply and discard it, then report the mechanism's failure. A caller is left with a session it can keep using rather than a stream out of step with its server.

### Requirement: Capability refresh
`ensure_capabilities` SHALL issue a `CAPABILITY` command after a successful exchange, since a server may change OWNER, LANGUAGE and MAXREDIRECTS per user. The coroutine SHALL NOT read a capability response it was not promised: RFC 5804 requires one only when a SASL security layer was negotiated, and no mechanism here negotiates one.
