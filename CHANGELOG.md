# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the I/O-free coroutine layer covering the whole of RFC 5804: the capability greeting, `CAPABILITY`, `STARTTLS`, `AUTHENTICATE`, `LOGOUT`, `NOOP`, `UNAUTHENTICATE`, `HAVESPACE`, `LISTSCRIPTS`, `GETSCRIPT`, `PUTSCRIPT`, `CHECKSCRIPT`, `SETACTIVE`, `DELETESCRIPT`, `RENAMESCRIPT` and a raw passthrough.

- Added `ManagesieveSessionOpen`, the composite coroutine covering transport selection, the greeting, the optional STARTTLS upgrade and the SASL exchange.

  It yields transport requests alongside reads and writes, so a caller on any runtime answers them with its own sockets and inherits the ordering.

- Added the std client behind the `client` feature: `ManagesieveClient` and `ManagesieveClientAsync` carry one method per coroutine, and `ManagesieveClientStd` implements the blocking one over any `Read + Write` stream.

  With a TLS feature enabled it also gains `connect`, which opens a whole authenticated session from a URL.

- Added `ManagesieveResponseCode`, so a missing script, a taken name, a quota, a referral and a compilation warning arrive as themselves rather than as text to grep.

- Added the refusal to send a password or a bearer token over a cleartext connection, which RFC 5804 section 5 asks implementations to carry; `allow_cleartext_auth` turns it off.

- Added the refusal of bytes arriving past the greeting or past the `STARTTLS` reply, which would otherwise be replayed inside the TLS session the upgrade opens.
