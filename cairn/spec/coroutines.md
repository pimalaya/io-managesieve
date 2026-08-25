---
cairn: spec
capability: coroutines
status: current
---

# Coroutines

Every ManageSieve exchange is exposed as an I/O-free coroutine: a resumable state machine emitting read and write requests instead of performing I/O. The caller owns the socket and pumps the coroutine. The contract is shared by every command and lives in the crate-root `coroutine` module.

### Requirement: Coroutine contract
Each command SHALL implement `ManagesieveCoroutine`, declaring `Yield` and `Return` associated types and a `resume(&mut self, arg: Option<&[u8]>)` method returning `ManagesieveCoroutineState<Yield, Return>` (`Yielded` or `Complete`). `Return` SHALL be `Result<Output, Error>`.

The resume argument SHALL be `None` for the initial call and after a write, `Some(data)` after a read, and `Some(&[])` for EOF.

### Requirement: Standard yield
`ManagesieveYield` SHALL carry `WantsRead` and `WantsWrite(Vec<u8>)`, each naming the caller's action rather than the coroutine's. Every command coroutine SHALL declare it. A coroutine needing more, which today is only the session opener, SHALL declare its own enum and SHALL provide `From<ManagesieveYield>` for it.

### Requirement: State naming
A coroutine's private `State` enum SHALL name each variant after the action in flight, as a present-tense verb (`Start`, `Write`, `Read`, `Cancel`). An `Await` or `Pending` prefix is banned. Each SHALL carry a `Display` impl reading the same way (`send putscript`, `read challenge`), and a state change SHALL be logged with `debug!("{}", self.state)`.

### Requirement: Base exchanges
`send::ManagesieveResponseRead` SHALL own the read side alone, for the greeting and the capability response following a TLS upgrade, which arrive unprompted. `send::ManagesieveCommandSend` SHALL be that coroutine with a write in front of it, and every command SHALL delegate to it, except the authentication exchange, which reads a line at a time because it answers each challenge before the response is over.

Both SHALL complete on `ManagesieveResponseReadOk`, carrying the parsed response and whatever arrived past it.

### Requirement: Error shape
Each command SHALL declare its own error enum, normalising to `"ManageSieve <COMMAND> failed: <cause>"`, with a `Rejected(ManagesieveCompletion)` variant for a NO or BYE and a `Send` variant wrapping the base exchange. RFC wire tokens SHALL keep their exact spelling.

### Requirement: Documented exchanges
Every command module SHALL open with a runnable example driving its pump loop, compiled as a doctest, since driving that loop correctly is the whole contract.
