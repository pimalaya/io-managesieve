---
cairn: change
id: local-server-testing
status: active
created: 2026-08-25
---

# Verify against a real server, driven from the devshell

The suite proves what the crate does with bytes. It cannot prove what a server does with ours, and the gap is not evenly spread: it sits almost entirely on the paths a scripted socket cannot produce, which are the paths a server's *configuration* produces.

The scripted server in tests/exchange.rs asserts the exact bytes each command sends, which is the right test for framing and the wrong one for interop: it only ever agrees with whoever wrote it. The SCRAM test replays the exchange published in RFC 7677 section 3, which proves the arithmetic and the base64 framing around it, and says nothing about whether a real server accepts what comes out. And `client/connect.rs` is the least covered file in the crate for the plain reason that its TLS arms need a TLS server.

So the missing tier is one real ManageSieve server, configured by us, reachable from the devshell. Configured by us is the load-bearing half: the untested paths are unlocked by server settings rather than by client calls, and no third-party account will have the ones we need.

## What

Add a second devShell carrying dovecot and its Sieve plugin, the way the fuzz shell is carried in io-sasl, so the fixture is pinned by this flake rather than by whatever a contributor has installed. nixpkgs has `dovecot` 2.4.4 and `dovecot_pigeonhole` 2.4.4, plus `dovecot_2_3` 2.3.21.1 with `dovecot_pigeonhole_0_5` for the older line, and `cyrus-imapd` 3.12.3. Dovecot 2.4 rewrote its configuration syntax, so a recipe found online will mostly be 2.3-shaped and the version pair has to be chosen deliberately rather than inherited.

Ship the server configuration in the repository next to a script that starts it on a loopback port, so a live run is one command rather than an afternoon. Then add an integration test tier that reads its endpoint from an environment variable and skips when it is unset, keeping the default suite and CI offline.

## What the configuration is actually for

Each setting exists to reach code no scripted socket can:

An `ssl = yes` listener reaches implicit TLS, the `sieves://` path nothing has ever run. It is the sharpest gap: the only live evidence we have says a server *rejected* it, while PACC assumes it exists and resolves ManageSieve at 4190 under implicit TLS. We have argued about that scheme twice without executing it once.

`auth_mechanisms` reaches SCRAM and CRAM-MD5 against a peer that did not learn the exchange from us. For SCRAM the specific unknown is whether the server-final arrives in the `SASL` response code of the OK or as a separate challenge line; the coroutine handles both and only a server says which is the real one. CRAM-MD5 is the server-first path, which no protocol crate in this family has run live, and it needs a password scheme the server can compute a digest from.

`sieve_quota_max_scripts`, `sieve_quota_max_storage` and `sieve_max_redirects` reach the response codes: `QUOTA/MAXSCRIPTS`, `QUOTA/MAXSIZE` and the `WARNINGS` text that drives what a caller prints on a stored script. `managesieve_sieve_capability` reaches capability parsing over values we did not write.

The literal cases come free once a real server is answering: a multi-line `NO` carrying a syntax error as a literal, a script name over the 1024 octets a quoted string allows, a name with a space that only LISTSCRIPTS returns literally.

## The pattern already exists in the family

io-imap and io-smtp each carry a `tests/stalwart.sh` that boots a real Stalwart server in a container, provisions an account over its management API, and runs an integration test against it; the reusable `pimalaya/nix` tests workflow takes a `docker` input for exactly that bootstrap step. Stalwart speaks ManageSieve, so that path is available here for the price of a script rather than a design.

The two are complementary rather than competing. Stalwart in a container is what continuous integration can run unattended, and it is the cheapest way to get *a* real server answering. Dovecot in a devshell is what reaches the configuration corners, since the untested paths are unlocked by settings and Dovecot is both the dominant implementation and the one whose Sieve knobs are worth exercising. Which of the two lands first is a scheduling question; whichever it is, the other should not be dropped for it.

## A second implementation

Cyrus timesieved is worth one run rather than a fixture. It is the divergence: it predates RFC 5804 in places, historically listened on port 2000, and a build without the `VERSION` capability carries no RENAMESCRIPT, CHECKSCRIPT or NOOP. That is the branch the error documentation describes and that nothing has produced, and it should surface as a clean rejection rather than a parse failure.

## Testing against a real account

Not part of this change, but the rule belongs somewhere: these commands decide what filters somebody's mail. A live run against a real account probes with CHECKSCRIPT, which compiles without storing, records LISTSCRIPTS before touching anything, uses a throwaway script name, and leaves SETACTIVE alone, since deactivating silently turns the account's filtering off. The consumer repository is where such a run is written up.
