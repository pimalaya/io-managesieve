---
cairn: delta
change: parser-hardening
---

## ADDED Requirements

### Requirement: Hand-written response parser
The response parser SHALL be hand-written rather than built on a parser-combinator library. Framing and tokenisation are one walk, a literal making a CRLF content rather than a line ending, and the reader SHALL keep a first-class incomplete outcome that a combinator library does not offer. A dependency SHALL NOT be introduced to restate the token-level grammar, which is flat and non-recursive.

### Requirement: Fuzzed response parser
The response parser SHALL be covered by coverage-guided fuzzing, the framing being hand-written index arithmetic over bytes chosen by a network peer. A target SHALL assert that arbitrary input always yields a response, an incomplete signal or a typed error, never a panic and never a non-terminating loop.

A second target SHALL assert chunk-split invariance: the same bytes delivered in arbitrary splits SHALL produce the outcome parsing the whole buffer produces. Chunk boundaries are where an incremental reader fails, and no enumerated unit test covers them.

The fuzz package SHALL be excluded from the measured coverage surface.
