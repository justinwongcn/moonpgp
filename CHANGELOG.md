# Changelog

All notable changes to `justinwongcn/openpgp` (moonpgp) are documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The module version lives in `moon.mod` (`version`); a section is only renamed to
a released version when that version is published to mooncakes.io.

## [Unreleased]

Nothing yet — the RFC 9580 v6/AEAD/Argon2 work landed in 0.1.0 below.

## [0.1.0] - 2026-10-08

First complete milestone: a pure-MoonBit OpenPGP (RFC 4880/9580) email
encryption, decryption, signing and verification library, interoperable with
GnuPG 2.4.5, OpenSSL 3.x, ProtonMail gopenpgp v3 and go-crypto v1.4.1.

### Added

- **ASCII Armor** — CRC-24 checksum, multi-block parsing, CRLF tolerance.
- **Packet engine** — RFC 9580 packet headers (old and new formats, partial
  lengths), PKESK v3 + v6, SKESK v4/v5/v6, PublicKey/SecretKey/SecretSubkey
  (v4 + v6), UserID, Signature v4 + v6 (with subpacket parsing), OnePassSig
  v3 + v6, Literal, Padding, Compressed, SEIPD v1 (MDC) and v2.
- **Symmetric encryption** — AES-128/192/256, OpenPGP-CFB with and without
  resync, MDC integrity protection.
- **S2K** — Simple / Salted / Iterated+Salted (SHA-256, SHA-1, RIPEMD-160,
  MD5) and Argon2 (specifier type 4, RFC 9580 §3.7.1.4).
- **Self-implemented primitives** (`src/primitives`) — BLAKE2b (RFC 7693),
  Argon2id (RFC 9106, v=0x13), HKDF-SHA256 (RFC 5869), with an explicit
  memory cap enforced *before* allocation when parsing untrusted messages.
- **RSA** — PKCS#1 v1.5 encryption, signing, verification, and key generation
  (Miller-Rabin, CRT, extended-Euclid modular inverse).
- **Ed25519** — EdDSA legacy (algorithm 22) signing/verification and key
  generation, self-implemented over `@bigint`.
- **X25519 / ECDH** — v6 (algorithm 25) native key wrap/unwrap with HKDF-SHA256
  (`info = "OpenPGP X25519"`) + AES-128 Key Wrap, addressed by fingerprint;
  Curve25519Legacy (algorithm 18) with the RFC 9580 §11.4 SHA-256 KDF and
  RFC 3394 key wrap in the PKESK v3 ephemeral-point format.
- **AEAD modes** — OCB (RFC 7253, MTI), EAX and GCM (RFC 9580
  §5.13.3–5.13.5), all three usable for v2 SEIPD, v5/v6 SKESK and usage-253
  secret keys.
- **v6 message encryption** — v6 PKESK (§5.1.2) + v2 SEIPD (§5.13.2) for v6
  X25519 subkeys, v6 SKESK (§5.3.2) for passphrases, v6 One-Pass Signatures,
  and the Features / Preferred AEAD Ciphersuites subpackets.
- **Key management** — transferable-key assembly/parsing, self-signatures and
  subkey binding signatures, passphrase locking/unlocking (usage 254 CFB and
  usage 253 AEAD + HKDF), armored import/export, keyring.
- **Signing** — inline, detached and cleartext (RFC 9580 §7) with text-mode
  CRLF normalisation.
- **Compression** — Compressed packet with ZIP (raw DEFLATE), ZLIB and
  uncompressed payloads; the decompressor supports dynamic Huffman coding.
- **MIME** — PGP/MIME (RFC 3156): `multipart/signed` construction and
  verification, `multipart/encrypted` parsing, RFC 5322 header parsing,
  Content-Type parameter parsing, Content-Transfer-Encoding decoding
  (base64/quoted-printable), byte-exact MIME tree parsing, body/attachment
  collection with gomime semantics, and one-shot `decrypt_mime` with callback
  delivery and the gopenpgp signature-status merge (Ok/NotSigned/NoVerifier/
  Failed).
- **Email assembly** (`src/mail`) — RFC 5322 headers (Date, Message-ID,
  atext-quoting addresses, RFC 2047 encoded words), multipart/mixed with the
  RFC 3156 §3 7-bit strategy, generalised `multipart/signed` over pre-built
  entities, and one-shot `build_encrypted_mail` (sign-then-encrypt).
- **Top-level API** — `pgp().encryption()/decryption()/key_generation()`
  builders and `KeyRing`.
- **CLI demo** — `cmd/main` with `keygen`, `edkeygen`, `v6keygen`, `encpass`,
  `decpass`, `encpub`, `decpriv`, `sign` and `verify` subcommands.
- **Examples** — `example/mailer` (SMTP submission over implicit TLS 465 or
  STARTTLS 587, with certificate pinning), `example/mailreader` (IMAP4rev1
  subset client) and `example/netmail` (wire transports).
- **Interoperability test suite** — GnuPG 2.4.5 in both directions, OpenSSL
  3.x, gopenpgp v3 test vectors, go-crypto v1.4.1 differentials, RFC 9580
  Appendix A.4/A.5/A.8–A.12, RFC 9106 §5.3, RFC 7693, RFC 5869, RFC 4493 and
  RFC 3394 Appendix B known-answer tests.
- **Documentation** — English and Chinese READMEs, plus
  `THIRD-PARTY-NOTICES.md` recording every dependency and test-vector source
  with its license.
- **CI / release tooling** — `scripts/acceptance.sh`,
  `scripts/interop_check.sh`, `scripts/interop_aead_gpg.sh`.

### Known limitations

- Ed25519/X25519 field arithmetic is **not constant time**; see the security
  notes in the README.
- The Argon2 fixtures from RFC 9580 Appendix A.5/A.12 are `#skip`ped by
  default because each derivation allocates 2 GiB.
- wasm-gc has no platform entropy source, so the 100 tests that generate key
  material (keygen, random IV/salt, Argon2) cannot run there; native, wasm and
  js run the full suite.
- `example/netmail` (and therefore the SMTP/IMAP transports) is native-only
  and is demo/test infrastructure rather than published library API.
