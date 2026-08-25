---
cairn: tasks
change: parser-hardening
---

- [ ] Add a `fuzz` package and its devShell, copying the shape io-sasl already carries
- [ ] Target one: `ManagesieveResponse::parse` over arbitrary bytes, asserting it always answers rather than panicking or looping
- [ ] Target two: the same bytes fed in arbitrary chunk splits, asserting the outcome matches parsing the whole buffer at once
- [ ] Assert the invariants a unit test states only by example: `consumed` within bounds, no allocation past `MAX_LITERAL`, a parsed response re-parsing identically from the bytes it consumed
- [ ] Keep the fuzz package out of the measured coverage surface, as tarpaulin.toml already does for the examples
- [ ] Record in CONTRIBUTING.md how to run the targets, and that a change to the lexer or the literal handling is worth a run
