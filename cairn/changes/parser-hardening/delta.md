---
cairn: delta
change: parser-hardening
---

## ADDED Requirements

### Requirement: Hand-written response parser
The response parser SHALL be hand-written rather than built on a parser-combinator library. Framing and tokenisation are one walk, a literal making a CRLF content rather than a line ending, and the reader SHALL keep a first-class incomplete outcome that a combinator library does not offer. A dependency SHALL NOT be introduced to restate the token-level grammar, which is flat and non-recursive.

### Requirement: Incremental reading
A coroutine reading a response SHALL read each byte once: a logical line arriving over several reads SHALL be searched for its line ending, lexed and copied a single time, and a line already read SHALL NOT be read again when the next one arrives. The work a response costs SHALL follow its size, whatever the number of reads a peer splits it over.

`ManagesieveResponseRead` and the authentication exchange SHALL share one line reader. `MAX_RESPONSE` SHALL bound the bytes of a whole response, the lines already read included, and in the authentication exchange the bytes of the line being read.

### Requirement: Reading cost
tests/drip.rs SHALL feed the readers a response a byte at a time under a counting allocator and assert that the bytes they allocate follow the size of the response rather than the number of reads. The assertion SHALL NOT rest on a clock.

### Requirement: Fuzz targets
The repository SHALL carry a cargo-fuzz package, unpublished and detached from the library's cargo workspace, the framing being hand-written index arithmetic over bytes chosen by a network peer. The nightly toolchain and cargo-fuzz it needs SHALL be exposed as the `fuzz` devShell of the repository flake.

A `parse` target SHALL assert that arbitrary input always yields a response, an incomplete signal or a typed error, never a panic and never a non-terminating loop, and that a response holds together: the bytes consumed within the buffer, no string longer than them, the same response from the same bytes.

A `read` target SHALL deliver the same bytes in arbitrary splits, followed by EOF, to `ManagesieveResponseRead` and to the authentication exchange. It SHALL assert split invariance, `ManagesieveResponseRead` standing after each read where `ManagesieveResponse::parse` stands on the bytes fed so far, and a cost bound, the bytes a reader allocates staying within a constant per byte fed whatever the number of reads. Neither reader SHALL ask for a read after EOF.

## MODIFIED Requirements

### Requirement: Coverage
Every line of the library SHOULD be reachable from a test, measured with cargo-tarpaulin over all features. Production code SHALL NOT be shaped to move the number: code no meaningful test can reach is deleted rather than covered, and code a tool misreads is documented rather than rewritten. The examples and the fuzz package SHALL be excluded from the measured surface, which tarpaulin.toml does.
