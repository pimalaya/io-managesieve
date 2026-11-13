---
cairn: log
change: parser-hardening
landed: 2026-11-13
---

# Parser hardening

The proposal of 2026-08-25 asked for a fuzz package over the hand-written framing. It lands with that package and with a fix the proposal did not know it needed, found by the family audit of 2026-11-13 (SIEVE-01 for the readers, SIEVE-05 for the missing targets).

**The readers read each byte once.** `ManagesieveResponseRead` appended each read to a buffer and called `ManagesieveResponse::parse` on all of it, and `ManagesieveAuthenticate` did the same a line at a time, so a response dripped in small reads was lexed again from its first byte at every read and its complete literals copied again. `utils::LineScan` is now a resumable scanner of one logical line: it keeps how far the segment was searched for its line ending, the tokens already lexed, and the end of the literal it is waiting for. `response::LineBuffer` owns the received bytes around it, hands out one `ManagesieveLine` at a time, and drops the lines already taken when the next read arrives. Both coroutines read through it. `ManagesieveResponse::parse` and `ManagesieveLine::parse` stay as the one-shot entries, built on the same scanner.

Nothing public moved. `MAX_RESPONSE` still bounds a whole response in `ManagesieveResponseRead`, now through a count of the bytes read since the buffer no longer holds the lines taken, and still bounds the line being read in the authentication exchange.

**The cost is asserted without a clock.** tests/drip.rs counts allocated bytes with a per-thread counting allocator. Against the old readers, one byte per read: a LISTSCRIPTS response of 400 scripts allocated 475,333,898 bytes against 29,472,638 for 100 scripts, 16.1 times for 4 times the size; a 64 KiB literal followed by 256 dripped bytes allocated 17,467,005 bytes in `ManagesieveResponseRead` and 17,072,283 in `ManagesieveAuthenticate`. Now: 174,634 against 43,726 (4.0 times), 262,653 and 262,299. A segment searched again for a line ending it does not hold yet allocates nothing, so a unit test on the scanner's cursor pins that half, next to one resuming every wire-level fixture at every split.

**The fuzz package.** fuzz/ follows io-sasl's layout: a detached cargo-fuzz package, its own shell.nix, two targets. `parse` holds `ManagesieveResponse::parse` to its three outcomes and to a response that parses again into itself. `read` feeds arbitrary splits to both readers and holds `ManagesieveResponseRead`, after each read, to what the one-shot parser says of the bytes fed so far, which the proposal wanted and which only means something now that the reader keeps state. It also holds both readers to an allocation bound of 4096 bytes plus 512 per byte fed. Run against the old readers, that bound fell in under a minute, on an input of 83 bytes that had allocated 46,754. Against the new ones: `read` 336,808 runs in 41 seconds, `parse` 763,400 runs in 21 seconds, no finding. The runs are not wired into continuous integration.

Verified: 108 unit tests, 13 integration tests and 17 doctests green with every feature, and the suite green with no default features, `client` alone, `url` alone and the default set.

Spec updated: `commands` (ADDED: "Hand-written response parser"), `coroutines` (ADDED: "Incremental reading"), `testing` (ADDED: "Reading cost", "Fuzz targets"; MODIFIED: "Coverage").
