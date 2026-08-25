# Contributing guide

Thank you for investing your time in contributing to I/O ManageSieve.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs: it is the architecture document of this crate;
4. the cairn/ folder for the development history and living plans (the Cairn convention: spec/, changes/, log/).

Everything below documents only what differs from the Pimalaya standards.

## One coroutine for every authentication mechanism

io-imap and io-smtp carry one module per SASL mechanism. This crate carries one, `rfc5804::authenticate`, and dispatches on `io_sasl::mechanism::Sasl` inside it. The reason is the protocol rather than a preference: those two frame each mechanism differently, IMAP through the `AuthMechanism` grammar of imap-types and SMTP through the AUTH command plus a per-mechanism capability refresh, while RFC 5804 frames them all identically, a mechanism name and a base64 string each way. A module per mechanism would be the same file twelve times.

Adding a mechanism to io-sasl therefore adds one arm to the private `Mechanism` enum, one arm to its `resume`, and one variant to `ManagesieveAuthenticateError`. A mechanism whose exchange is not the standard challenge-response, which today means the two Kerberos relays, is refused by name instead: framing one takes a yield vocabulary this coroutine does not have, and pretending otherwise would send the caller's own token where the server's challenge belongs.

## Deviations from io-imap and io-smtp

Three, each with a reason worth keeping:

A coroutine refuses trailing bytes rather than handing them back. `SmtpStartTls` returns whatever arrived past the `220` and leaves the caller to check it; `ManagesieveStartTls` and `ManagesieveGreetingGet` fail instead. Nothing legitimate follows either response, the caller is about to open a TLS session those bytes would be replayed inside, and a returned `Vec<u8>` is something a caller can ignore.

The session refuses cleartext credentials by default. RFC 5804 section 5 asks implementations to carry a configuration where a mechanism vulnerable to passive eavesdropping cannot run without an encryption layer, and this is that configuration; `ManagesieveSessionOpenOptions::allow_cleartext_auth` opts out. PLAIN, LOGIN, OAUTHBEARER and XOAUTH2 are the four mechanisms it covers, being the ones that hand an observer something replayable.

The response parser is one pass rather than `is_complete` then `parse`. Finding where a response ends means walking its literals, which is the same walk as reading its tokens, so `ManagesieveResponse::parse` answers `None` while the response is incomplete and returns the response plus the bytes it consumed once it is.

## Feature matrix

`client` gates the std-blocking client, the blessed std-gating. Each TLS feature implies it, selects the pimalaya-stream provider, and pulls `anyhow` and `url`.

`scram` pulls the crypto crates the SCRAM exchange needs plus `rand` for the client nonce the std client draws. It enables both io-sasl SCRAM features rather than one: RFC 5804 section 2.1 tells client implementations to implement SCRAM-SHA-1, so a default build carrying only the SHA-2 profiles would not conform.

`cram-md5` adds the legacy digest mechanism and stays off, so a build gets a weak mechanism only by asking for it. It is worth having at all because ManageSieve is the one protocol in this family whose framing carries a server-first mechanism without a special case.

SASLprep is enabled on the io-sasl dependency rather than left to the default set, since RFC 5804 section 2.1 requires both client and server to prepare the authorization identity.

Build the shapes that differ:

```sh
cargo build --no-default-features             # the coroutines alone, no_std
cargo build --no-default-features -F client   # the client over a caller-owned stream
cargo build                                   # the full client, rustls and SCRAM
cargo build --all-features                    # the legacy mechanism too
```

## Tests

Three layers. The unit tests next to each coroutine feed it bytes and pin what it puts on the wire and what it makes of the reply, in the shape io-imap's auth coroutines set: a success, a rejection, an EOF, plus whatever that command gets wrong on its own. The lexer and the response parser carry their own, since every command rests on them and the cases that matter there (a literal resuming a line, a response code holding one, a name that cannot be quoted) never show up in a command test. tests/exchange.rs drives the public client against a scripted server over a real socket, asserting the exact bytes each command sends, so the framing, the serialisers, the parser and the pump have to agree; it also replays the SCRAM-SHA-256 exchange published in RFC 7677 section 3 and checks that a server answering OK without a server-final is refused. tests/mechanisms.rs sweeps every mechanism the build enables and asserts each goes out under the name it is registered with, which is the one mistake a dozen near-identical dispatch arms actually make.

The example opening each module is a fourth layer, thin but load-bearing: it is the pump loop a consumer copies, and it runs as a doctest.

```sh
cargo test --no-default-features
cargo test
cargo test --all-features
```

## Coverage

The crate is small enough to keep almost fully covered, and it stays that way:

```sh
cargo tarpaulin --all-features --skip-clean --out Stdout
```

Never twist the code to move the number. Code no test can reach is either dead, and goes, or is worth a test that means something on its own.

The number to expect is 89.37%, which is what both the default ptrace engine and the `--engine llvm` one CI uses report, so a figure from either is comparable. The gap is almost entirely the `Display` impl of a `State` enum. A coroutine logs a state change with `debug!("{}", self.state)`, which a test run with no logger installed never formats, and a single-state coroutine never changes state at all, so the impl of the reference template is dead in both directions. Those, the `Default` impls delegating to `new`, and the TLS arms of `client/connect.rs`, which need a TLS server to reach, are what the run counts short. A drop below that figure should be treated as untested code until a mutation shows otherwise.

## What belongs elsewhere

Sieve itself. This library never parses a script: the server compiles it and reports where it went wrong, which is the whole point of `CHECKSCRIPT`. A caller wanting to validate locally reaches for a Sieve implementation, not for this crate.

Authentication payloads. io-sasl computes what a mechanism sends and checks what it receives; this crate carries the bytes, base64-encodes them and frames them. A mismatched server signature is io-sasl's failure, a challenge arriving where the grammar has none is this crate's.

Sockets and TLS. pimalaya-stream opens them, and only under the client feature. The coroutines name a transport and never touch one.
