# netmail — a working PGP email client, kept as an example

This package is **an example, not library API**. It exists because email is
the most common OpenPGP use case, and the MoonBit ecosystem had no IMAP/SMTP
client to reuse — so this package implements just enough protocol to
demonstrate the whole round trip end to end: fetch mail over IMAP, decrypt
and verify it with the `api` package, compose a PGP/MIME reply with `mail`,
and send it over SMTP (with optional TLS).

What that means for you:

- The library API lives in the root package plus `mime` and `mail`. Depend on
  those; do not depend on this package.
- Nothing here promises API stability. Public types and functions can change
  or disappear whenever the demo needs them to.
- It runs on native targets only (it needs sockets and TLS).
- The socket/TLS adapters contain toolchain workarounds (see the notes in
  `fd_sock.mbt` and `transport.mbt`); they are revisited on toolchain
  upgrades and are deliberately kept inside this package so the library
  itself stays clean.

If you need a real mail client, treat this as a reference to adapt, not a
dependency to take.
