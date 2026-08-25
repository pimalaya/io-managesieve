---
cairn: tasks
change: local-server-testing
---

- [ ] Add a `server` devShell to the flake carrying dovecot and dovecot_pigeonhole, pinning the version pair deliberately (2.4 changed the configuration syntax)
- [ ] Ship a Dovecot configuration and a start script binding loopback ports, one cleartext with STARTTLS and one with `ssl = yes`
- [ ] Configure `auth_mechanisms` for plain, login, scram-sha-1, scram-sha-256 and cram-md5, with a password scheme the digest mechanism can work from
- [ ] Configure `sieve_quota_max_scripts`, `sieve_quota_max_storage` and `sieve_max_redirects` so the quota and warning response codes are reachable
- [ ] Add an integration tier reading its endpoint from an environment variable and skipping when unset, so the default suite and CI stay offline
- [ ] Cover implicit TLS through `sieves://`, which nothing has ever executed
- [ ] Cover SCRAM and CRAM-MD5 against the server, recording whether the server-final arrives in the `SASL` response code or as a separate challenge
- [ ] Cover the literal cases a real server produces: a multi-line `NO`, a name past the quoted-string limit, a name carrying a space
- [ ] Run once against cyrus-imapd and record how a server without the `VERSION` capability answers RENAMESCRIPT, CHECKSCRIPT and NOOP
- [ ] Fold the results into cairn/spec/testing.md, then write the log
