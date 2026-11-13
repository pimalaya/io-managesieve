---
cairn: tasks
change: parser-hardening
---

- [x] Add a `fuzz` package and its fuzz/shell.nix, copying the shape io-sasl already carries
- [ ] Expose fuzz/shell.nix as the `fuzz` devShell in flake.nix, the way io-sasl's flake does (held on 2026-11-13: flake.nix carried an unrelated uncommitted edit)
- [x] Target one, `parse`: `ManagesieveResponse::parse` over arbitrary bytes, asserting it always answers rather than panicking or looping
- [x] Target two, `read`: the same bytes fed in arbitrary splits to `ManagesieveResponseRead`, asserting after each read the outcome parsing the bytes fed so far gives
- [x] Assert the invariants a unit test states only by example: `consumed` within bounds, no string longer than the bytes consumed, a parsed response re-parsing identically from the bytes it consumed
- [x] Keep the fuzz package out of the measured coverage surface, as tarpaulin.toml already does for the examples
- [x] Record in CONTRIBUTING.md how to run the targets, and that a change to the lexer or the literal handling is worth a run
- [x] Read a response incrementally: a resumable line scanner, and a line buffer shared by `ManagesieveResponseRead` and `ManagesieveAuthenticate` (family audit of 2026-11-13, SIEVE-01)
- [x] Give the `read` target a cost oracle, allocated bytes bounded by the bytes fed, and feed the authentication exchange the same reads (SIEVE-05)
- [x] tests/drip.rs: the same bound as regression tests, failing against the readers that started over at each read
