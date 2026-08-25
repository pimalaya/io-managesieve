---
cairn: spec
capability: client
status: current
---

# Client

The `client` feature gates a std-blocking client and the two traits carrying its command surface. It is the only place this crate touches a socket.

### Requirement: Command surface
`ManagesieveClient` and `ManagesieveClientAsync` SHALL each require one method, `run`, pumping a coroutine against the implementor's transport, and SHALL carry one default body per command. The two SHALL be emitted from a single list of delegations, so a command added to one cannot be missing from the other.

`run` SHALL be bound to `Yield = ManagesieveYield`, which admits exactly the coroutines every client wraps identically. The session opener declares its own vocabulary and SHALL be wired per implementation instead.

### Requirement: Send on the async surface only
`ManagesieveClientAsync` SHALL declare `Send` as a supertrait and SHALL declare the future `run` returns as `impl Future<..> + Send`, since a plain `async fn` in a trait cannot promise a `Send` future and every default body would then fail under a spawning runtime. `ManagesieveClient` SHALL carry no such bound, a blocking call returning a value and the bound excluding a thread-affine transport.

### Requirement: Blocking implementation
`ManagesieveClientStd` SHALL hold a single `Box<dyn ManagesieveStream>`, auto-implemented for any blocking `Read + Write + Send + 'static`. `new` SHALL take a pre-connected stream, and `set_stream` SHALL replace it after a caller-managed upgrade.

### Requirement: End-to-end connect
With a TLS feature enabled, `ManagesieveClientStd::connect` SHALL open a whole authenticated session from a URL, answering the session coroutine's transport requests with a `pimalaya_stream::stream::Stream`. It SHALL own no protocol decision of its own, and SHALL draw a SCRAM client nonce when the credentials carry an empty one, that being the one thing an I/O-free coroutine cannot do.
