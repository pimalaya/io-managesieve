---
cairn: delta
change: local-server-testing
---

## ADDED Requirements

### Requirement: Local server verification
The repository SHALL carry a real ManageSieve server as a test fixture, pinned by the flake rather than by whatever a contributor has installed, and configured here rather than taken as given: the paths a scripted socket cannot produce are unlocked by server settings, and no third-party account carries the ones this crate needs.

The fixture SHALL reach, at least: implicit TLS on a `sieves://` endpoint, a STARTTLS upgrade on a cleartext one, the SCRAM and CRAM-MD5 mechanisms, and the quota and warning response codes.

An integration tier SHALL drive the fixture, reading its endpoint from an environment variable and skipping when that variable is unset, so the default suite and continuous integration stay offline and need no server.

### Requirement: A second implementation
The crate SHALL be run at least once against a ManageSieve server other than Dovecot, and the result recorded. A server without the `VERSION` capability carries no RENAMESCRIPT, CHECKSCRIPT or NOOP, and that refusal SHALL surface as a rejection carrying the server's own text rather than as a parse failure.

## MODIFIED Requirements

### Requirement: Whole exchanges
`tests/exchange.rs` SHALL drive the public client against a scripted server over a real socket, asserting the exact bytes each command sends, so the framing, the serialisers, the parser and the pump have to agree. `tests/mechanisms.rs` SHALL sweep every mechanism the build enables and assert each goes out under the name it is registered with, a dozen near-identical arms being where two of them land on the same place.

Neither proves interop, and neither SHALL be read as doing so: a scripted server only ever agrees with whoever wrote it, and a replayed specification vector proves the arithmetic rather than the acceptance. What a server does with these bytes is settled by the local server fixture.
