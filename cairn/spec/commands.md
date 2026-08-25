---
cairn: spec
capability: commands
status: current
---

# Commands

RFC 5804 is a single specification, so `rfc5804` holds the whole protocol, one module per command plus the two modules the commands share.

### Requirement: Command coverage
The crate SHALL carry a coroutine for every command RFC 5804 defines: the capability greeting, `CAPABILITY`, `STARTTLS`, `AUTHENTICATE`, `LOGOUT`, `NOOP`, `UNAUTHENTICATE`, `HAVESPACE`, `LISTSCRIPTS`, `GETSCRIPT`, `PUTSCRIPT`, `CHECKSCRIPT`, `SETACTIVE`, `DELETESCRIPT` and `RENAMESCRIPT`, plus a raw passthrough for anything a later extension adds.

### Requirement: Command serialisation
Each command SHALL be a `Managesieve*Command` struct with public fields, serialisable to wire bytes through `From<Cmd> for Vec<u8>`. A string SHALL travel quoted when it fits the 1024 octets RFC 5804 section 4 allows and holds no control character, and as a non-synchronising literal otherwise, so a whole command travels in one write.

### Requirement: Response framing
`rfc5804::response` SHALL parse a response once for every command: zero or more data lines, then a completion line. A logical line SHALL span as many physical lines as it has literals. `ManagesieveResponse::parse` SHALL answer `None` while the response is incomplete and return the response with the bytes it consumed once it is, scanning for the end and reading the tokens being the same walk over the literals.

The completion SHALL carry a parsed `ManagesieveResponseCode` where the server sent one, modelling the eleven RFC 5804 section 1.3 defines and keeping the name of anything else in `Other`. A `QUOTA` detail the crate does not know SHALL be read as `QUOTA`, as the specification asks.

### Requirement: Capabilities
`rfc5804::capability` SHALL hold `ManagesieveCapabilities`, with an accessor per capability the specification defines and `value`/`has` for anything else, so a capability registered later stays reachable. Parsing SHALL skip a line it cannot read rather than failing the set.

### Requirement: Raw passthrough
The raw coroutine SHALL send what the caller wrote, adding the CRLF when it is missing, and SHALL return the parsed response rather than an interpretation of it: a NO or BYE reaches the caller as itself.

### Requirement: Injection refusal
The greeting coroutine and the STARTTLS coroutine SHALL fail when the server sends bytes past their response, rather than returning them. Nothing legitimate follows either, and the caller is about to open a TLS session those bytes would be replayed inside.
