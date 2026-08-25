---
cairn: log
change: bootstrap
landed: 2026-08-25
---

# io-managesieve

The crate lands whole rather than in pieces, extracted from the ManageSieve support that had gone into Himalaya as a hand-rolled lexer, a blocking socket loop and a two-mechanism SASL exchange. That code was correct enough to work against Dovecot and wrong in its layering: RFC 5804 is not Himalaya's, and nothing else in the project could reach it where it sat. This repository is the same protocol written where io-imap and io-smtp already are, and almost none of the original survived the move.

## What the shape bought

The largest gain was authentication, and it came free. io-imap carries a module per SASL mechanism, io-smtp another, and each is a hundred and fifty lines of framing around one io-sasl call. That duplication is theirs by necessity: IMAP frames a mechanism through imap-types' `AuthMechanism` grammar and SMTP through the AUTH command plus a per-mechanism capability refresh, so the shape genuinely differs each time. ManageSieve frames every mechanism identically, a name and a base64 string each way, which means one coroutine dispatching on `io_sasl::mechanism::Sasl` covers all of them. Ten arms, one file, and adding a mechanism to io-sasl costs one more.

CRAM-MD5 is the visible consequence. It is server-first, and neither of the older crates carries it; here it needed nothing, because a mechanism answering the first resume with `WantsRead` simply has no initial response to inline and the command goes out bare. LOGIN needed the opposite care: io-sasl computes its username without a challenge, so it looks client-first from the outside, but draft-murchison-sasl-login is server-first and RFC 5804 section 2.1 tells servers to reject an initial response for a mechanism that speaks second. The coroutine therefore never inlines LOGIN, whatever the options say, and `tests/mechanisms.rs` pins that.

Response codes were the second gain. The Himalaya parser kept a completion line as text, so `NO (NONEXISTENT)` and `NO (QUOTA/MAXSIZE)` reached a caller as the same shape. `ManagesieveResponseCode` models the eleven the specification defines, keeps the name of anything else, and folds an unknown `QUOTA` detail back onto its parent as clients are asked to. That is what lets `sieve put` report a WARNINGS text and a caller tell a missing script from a full mailbox.

The third was simply coverage: RENAMESCRIPT, NOOP and UNAUTHENTICATE were missing and are here.

## Three deliberate deviations

A coroutine refuses trailing bytes rather than handing them back. `SmtpStartTls` returns whatever arrived past the 220 and leaves the caller to check it, which is a check a caller can forget; `ManagesieveStartTls` and `ManagesieveGreetingGet` fail instead. Nothing legitimate follows either response, and the session about to be opened is exactly the one those bytes would be replayed inside.

The session refuses cleartext credentials by default. RFC 5804 section 5 asks for a configuration where a mechanism vulnerable to passive eavesdropping cannot run without an encryption layer, and this crate makes that configuration the default rather than an option somebody has to find. PLAIN, LOGIN, OAUTHBEARER and XOAUTH2 are the four it covers; SCRAM and CRAM-MD5 disclose no password and are unaffected.

The response parser is one pass rather than io-smtp's `is_complete` then `parse`. Finding where a ManageSieve response ends means walking its literals, which is the same walk as reading its tokens, so doing it twice would be doing it twice.

## The framing, and why it needed a lexer

ManageSieve borrows ACAP's data types, and the consequence that bites is that a literal does not end a line: `{15}` is followed by CRLF, then fifteen octets, then the rest of the same logical line. `LISTSCRIPTS` uses that for a script name carrying a space, and the `TAG` response code of `NOOP` uses it inside parentheses. So `scan_line` reads a logical line across as many physical ones as it has literals, and everything above it, the response parser included, sees tokens rather than bytes. A regular-expression approach to the same grammar is what the extracted code did, and it is what made a script name with a newline in it unrepresentable.

## Cancellation

When a mechanism refuses what the server said, the exchange is cancelled with the `"*"` string RFC 5804 section 2.1 gives clients, the reply is read and discarded, and the mechanism's own failure is what reaches the caller. Neither io-imap nor io-smtp does this, and the reason to is that a caller holding a session it can keep using is worth more than one holding a stream out of step with its server.

## Verification

105 unit tests, 10 integration tests and 17 doctests pass with every feature enabled, and the suite passes across the feature matrix (no default features, `client` alone, the default set, all features, and each TLS provider). `cargo clippy --all-features --all-targets` and `cargo deny check` are clean.

Two of the integration tests are worth naming. One replays the SCRAM-SHA-256 exchange published in RFC 7677 section 3, base64 as ManageSieve carries it, with the server-final riding in the `SASL` response code: that is what proves the framing carries SCRAM rather than merely compiling against it. The other gives the same credentials a server that answers OK without ever sending a server-final, and the exchange fails, because a success reply cannot stand in for a proof the server never gave.

Coverage reads 89.37%. What it counts short is dominated by the `Display` impl of a `State` enum, which a test run installs no logger to format and which a single-state coroutine never reaches anyway, and by the TLS arms of the connect helper, which need a TLS server.

Capabilities moved: coroutines, commands, authentication, session, client, packaging, testing.
