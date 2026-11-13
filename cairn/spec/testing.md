---
cairn: spec
capability: testing
status: current
---

# Testing

### Requirement: Unit tests per coroutine
Each command module SHALL carry unit tests feeding the coroutine bytes: a success, a rejection, an EOF, and whatever that command gets wrong on its own. They SHALL pin the exact bytes the command puts on the wire.

### Requirement: Wire-level tests
The lexer and the response parser SHALL carry their own tests, every command resting on them and the cases that matter there never showing up in a command test: a literal resuming a logical line, a response code holding one, a name that cannot be quoted, a malformed marker, a hostile size.

### Requirement: Whole exchanges
tests/exchange.rs SHALL drive the public client against a scripted server over a real socket, asserting the exact bytes each command sends, so the framing, the serialisers, the parser and the pump have to agree. tests/mechanisms.rs SHALL sweep every mechanism the build enables and assert each goes out under the name it is registered with, a dozen near-identical arms being where two of them land on the same place.

### Requirement: Reading cost
tests/drip.rs SHALL feed the readers a response a byte at a time under a counting allocator and assert that the bytes they allocate follow the size of the response rather than the number of reads. The assertion SHALL NOT rest on a clock.

### Requirement: Feature matrix
The test suite SHALL pass with no default features, with the default set, and with all features, each compiling a different set of mechanisms and layers.

### Requirement: Coverage
Every line of the library SHOULD be reachable from a test, measured with cargo-tarpaulin over all features. Production code SHALL NOT be shaped to move the number: code no meaningful test can reach is deleted rather than covered, and code a tool misreads is documented rather than rewritten. The examples and the fuzz package SHALL be excluded from the measured surface, which tarpaulin.toml does.

### Requirement: Fuzz targets
The repository SHALL carry a cargo-fuzz package, unpublished and detached from the library's cargo workspace, the framing being hand-written index arithmetic over bytes chosen by a network peer. The nightly toolchain and cargo-fuzz it needs SHALL be exposed as the `fuzz` devShell of the repository flake.

A `parse` target SHALL assert that arbitrary input always yields a response, an incomplete signal or a typed error, never a panic and never a non-terminating loop, and that a response holds together: the bytes consumed within the buffer, no string longer than them, the same response from the same bytes.

A `read` target SHALL deliver the same bytes in arbitrary splits, followed by EOF, to `ManagesieveResponseRead` and to the authentication exchange. It SHALL assert split invariance, `ManagesieveResponseRead` standing after each read where `ManagesieveResponse::parse` stands on the bytes fed so far, and a cost bound, the bytes a reader allocates staying within a constant per byte fed whatever the number of reads. Neither reader SHALL ask for a read after EOF.
