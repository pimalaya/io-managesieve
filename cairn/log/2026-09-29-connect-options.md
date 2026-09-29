---
cairn: log
change: connect-options
landed: 2026-09-29
---

# Connect options

Requested in pimalaya/himalaya#742: a per-account proxy. pimalaya-stream already tunnels through SOCKS5 and HTTP CONNECT, but `connect` always asked it for `Proxy::System`, so a caller could only reach a proxy through the environment.

**`ManagesieveClientStdConnectOptions`** (client/connect.rs) replaces every optional argument of `ManagesieveClientStd::connect`, which now takes `(url, opts)`. Its fields are `tls`, `proxy`, `sasl` (now a plain `Option<Sasl>`) and `session`, the unchanged `ManagesieveSessionOpenOptions`. The URL stays an argument because it is the only input without a default. The same shape lands across io-imap, io-smtp, io-jmap, io-gmail and io-msgraph, so one setting reaches every Pimalaya client the same way.

**The proxy** reaches the TCP and TLS connects; STARTTLS upgrades the already tunnelled stream and a local socket ignores it. The default stays `Proxy::System`.

**Breaking**: the signature of `connect`.

Verified: unit and exchange tests green, the two end-to-end connect tests ported to the options.

Spec updated: `client` (MODIFIED: "End-to-end connect").
