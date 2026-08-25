---
cairn: change
id: parser-hardening
status: active
created: 2026-08-25
---

# Trust the response parser, and why not through chumsky

The framing lives in 291 lines of hand-written index arithmetic over bytes a network peer chose. That is the part of this crate most worth being nervous about, and the nervousness is well placed: `scan_line` slices on offsets it computed itself, the quoted-string lexer reads `segment[index + 1]` after a backslash, and the literal marker turns an attacker-supplied number into a length. Rust bounds-checks all of it, so the failure mode is a panic rather than memory corruption, but a panic inside a no_std library is still a denial of service handed to whoever runs the server.

The obvious move is a parser-combinator library, and the obvious candidate is chumsky, since io-smtp already parses with it. This proposal records why that does not fit here, so the question is answered once rather than every time somebody reads utils.rs, and proposes what actually addresses the concern.

## Why the io-smtp precedent does not transfer

io-smtp splits its reading in two. `SmtpResponse::is_complete` is hand-written and fourteen lines long: a reply ends when the last line has a space at index three. `SmtpResponse::parse` is chumsky, run over the complete slice that check approved. The split works because in SMTP those two questions are genuinely separate, and the first one is trivial.

ManageSieve does not offer that split, because of literals. A `{n}` marker means the next n octets are content, CRLFs and quotes included, after which the same logical line resumes. Finding where a response ends therefore requires walking every token, since a CRLF inside a literal is not a line ending and a CRLF outside one is. Framing and lexing are the same walk. That is already documented as the reason `ManagesieveResponse::parse` is one pass returning `Option<(response, consumed)>` rather than a completeness check followed by a parse.

That leaves nowhere good to put chumsky. It parses a complete input and has no first-class "not yet, send more bytes" outcome; the closest is inferring incompleteness from an end-of-input error, which makes a truncated response and a malformed one indistinguishable unless the code reaches into the error internals of a library it does not own. So either the incremental scanner stays hand-written and chumsky gets the leftovers, or the coroutine contract gets worse.

## What would actually be left for it

The leftovers are small. After tokenisation the grammar is roughly 116 lines: a data line is a string and maybe a second token, a completion is one of three atoms with an optional parenthesised code and an optional string, a response code is a name with an optional slash detail and an optional argument. Flat, non-recursive, no precedence, no ambiguity. Combinators earn their keep on grammars that nest; this one does not.

Cost is not the objection. With `default-features = false` chumsky pulls only hashbrown, unicode-ident and unicode-segmentation, which is modest and already proven to work in a no_std crate here. The objection is fit: a dependency that cannot touch the risky 291 lines and would restate the safe 116 as combinators is motion rather than progress.

## What to do instead

Fuzz the parser. It addresses the actual risk, which is the index arithmetic, rather than the aesthetic one. io-sasl already carries a `fuzz/` package with its own devShell, so the pattern and the nix plumbing are settled and can be copied rather than designed.

Two targets suggest themselves. One drives `ManagesieveResponse::parse` with arbitrary bytes and asserts it always answers: a response, an incomplete signal, or a typed error, never a panic and never an infinite loop. The second is the property worth having most, and it is not a smoke test: feed the parser arbitrary bytes in arbitrary chunk splits and assert the outcome is identical to parsing the whole buffer at once. Chunk-boundary handling is where an incremental reader actually goes wrong, and no unit test enumerates those splits.

Worth asserting alongside: `consumed` never exceeds the buffer, a literal never allocates past `MAX_LITERAL`, and a response that parses re-parses identically from the bytes it consumed.

## What would change the answer

Two things, neither of them near. If the response-code grammar were ever exposed in full, `extension-data` is recursive in the RFC 5804 ABNF and nested parentheses are where combinators start paying; today unknown codes keep their name and discard their arguments, which is what clients are told to do. And if a Sieve-language parser ever landed in this crate, chumsky would be the right tool for it, which is precisely why it never will: the server compiles the script and says where it went wrong, and CHECKSCRIPT exists so a client does not have to.
