# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The module version lives in `moon.mod` (`version`); a section is only renamed to
a released version when that version is published to mooncakes.io.

## [Unreleased]

### Fixed — second review round N1–N10 (2026-10-26)

- **N1 (P1, security)**: a subkey packet without a SubkeyBinding signature
  is now rejected at import (RFC 9580 §10.1). Previously such a subkey was
  accepted and treated as encryption-capable with "all capabilities",
  so a subkey injected into a forwarded public key received the mail
  without any authentication by the primary key (probe-verified exploit).
- **N2**: transferable keys keep EVERY bound subkey (`PublicKey::subkeys :
  Array[SubkeyCert]` / `PrivateKey::subkeys : Array[SecretSubkeyCert]`,
  each carrying its own binding and revocation) instead of only the last
  one. Encryption selection judges each subkey by its own key flags, and
  document signatures issued by a signing subkey verify against the
  certificate. **Breaking**: replaces the `encryption_subkey` /
  `subkey_binding` / `subkey_revocation` fields.
- **N3**: persona (0x11) and casual (0x12) self-certifications bind a
  User ID like positive ones; keys certified only that way now import.
- **N4**: password decryption tries every SKESK in the message — the
  retry spans the payload decryption, so a wrong passphrase whose v4 SKESK
  unwraps to plausible garbage still falls through at the SEIPD integrity
  check. The encryption builder now seals to every configured passphrase
  (one SKESK each, shared session key) instead of silently using only the
  first, and the decryption builder tries all configured passphrases.
- **N5**: the decryption builder consults the configured verifiers even
  with several decryption keys (best-ranked status per gopenpgp's
  prioritizeSignatureErrors), instead of silently returning "no signature".
- **N6 (documented)**: old-format indeterminate-length packets consume the
  rest of the stream by design (go-crypto parity); the limitation is now
  documented at the parse site.
- **N7**: a cryptographically valid subkey signature is `Expired` (not
  `Ok`) when the primary key has expired.
- **N8**: v5 (RFC 4880bis draft) key packets are rejected at parse with a
  clear message instead of parsing and failing at first use.
- **N9**: `sign_inline` / `sign_and_encrypt` gained `file_name?` (default
  "message.txt"); the encryption builder passes its `file_name` through
  the sign+encrypt path too.
- **N10**: comment typo in `packet/sig.mbt` ("v0.16 subpacket" → type 16
  Issuer Key ID).
- Gates: 8 new regression tests (subkey injection, dual-subkey selection
  and subkey signing, persona/casual import, two-password messages,
  multi-key builder verification, expired-primary subkey signatures, v5
  rejection, file_name). `moon test` 414/414.

### Added — root facade package (2026-10-12)

- `import "justinwongcn/moonpgp"` now gives the complete high-level
  workflow directly (`@moonpgp.*`): the full `@api` surface (11 types, 27
  functions, `DEFAULT_MAX_DECOMPRESSED_BYTES`) re-exported via `pub using`,
  plus the option types used in those signatures (`@cipher.AeadMode`,
  `@compress.CompressedAlgo`, `@primitives.CipherAlgo` / `HashId`).
  Types keep their owning package, so methods resolve through the usual
  owner loading. Black-box acceptance tests cover the consumer workflow
  (password and key roundtrips, `pub(all)` enum pattern matching, builder
  chains, sign/verify). README / README.zh-CN.md quick-start updated.

### Changed — file splits, zero public-API change (2026-10-12)

- `api/key.mbt` (1227 lines) → `key.mbt` (types + accessors),
  `key_signing.mbt` (PKI adapters, self-signature machinery,
  `verify_key_signature`), `key_generate.mbt` (secret-key packet builders
  + the three `generate_*` entry points), `key_codec.mbt` (serialization
  + import parsing). All same-package `///|` block moves;
  `api/pkg.generated.mbti`: zero diff.
- `example/netmail/imap.mbt` (845 lines) → `imap.mbt` (client state +
  protocol state machine + session helpers), `imap_syntax.mbt`
  (logical-line/literal reading, quote/paren/atom scanners),
  `imap_fetch.mbt` (FETCH summaries + full-message fetch). The 627-line
  `imap_wbtest.mbt` is untouched; `example/netmail/pkg.generated.mbti`:
  zero diff.
- Gates: `moon check --target all --deny-warn` 0 errors / 0 warnings,
  `moon fmt --check` clean; native 389/389, wasm 381/381, js 381/381
  (previous baselines 385/377/377 + 4 new root-facade tests per target).

### Added — gopenpgp v3 gap closure (2026-10-11, plan
[`docs/plan-gap-closure-gopenpgp.md`](../docs/plan-gap-closure-gopenpgp.md))

- **Key lifecycle (M1)**: import-time cryptographic validation of every
  User-ID certification, subkey binding and (v6) Direct Key signature;
  `is_expired` / `is_revoked` / `can_encrypt` / `can_verify` on both key
  types (gopenpgp-aligned, `now = 0` disables time checks on the
  clockless targets); revocation signatures (0x20/0x28) parsed, verified
  lazily, and enforced at key selection; `KeyRing::find_encryption_key` /
  `find_verification_key` now take an optional `now`, consult key flags
  and cover all public-key algorithms (they were RSA-only).
- **Legacy symmetric ciphers (M2)**: self-implemented CAST5 (RFC 2144,
  KATs from Appendix B + OpenSSL cross-checks) and 3DES (FIPS 46-3,
  OpenSSL `des-ede3-ecb` cross-checks, EDE-degeneracy test), wired into
  the read side only: SEIPD v1 payloads, S2K derivation, usage-254/255
  secret-key unlocking, and GnuPG `--allow-old-cipher-algos` messages in
  both algorithms. Generation still emits AES only. Also fixed a latent
  bug the new fixtures exposed: the SEIPD v1 quick-check and inner-slice
  offsets were hardcoded to 16-byte blocks, so no 8-byte-block cipher
  (CAST5/3DES) could ever decrypt.
- **Session keys (M3)**: `SessionKey` type with validated construction,
  `generate_session_key`, bare-SEIPD `encrypt_to_session_key` /
  `decrypt_to_session_key` (out-of-band key), and
  `recover_session_key_with_password` / `recover_session_key_with_key`
  (gopenpgp `RetrieveSessionKey` analogs).
- **Compression (M4)**: optional ZIP/ZLIB compression on every
  encryption entry point and the builder (`EncryptionBuilder::compress`),
  output byte-verified by GnuPG; `DEFAULT_MAX_DECOMPRESSED_BYTES`
  (512 MiB) ceiling with `max_decompressed` overrides on the decrypt
  entry points and `DecryptionBuilder::max_decompressed`, enforced by
  allocation-bounded streaming decompression (flate limited inflate /
  chunked zlib decoder).
- **Multiple User IDs (M5)**: transferable keys carry every certified
  User ID (`user_ids : Array[UserIdBinding]`, wire order preserved,
  last certification per User ID wins); `user_id()` / `self_signature()`
  accessors keep the previous single-uid ergonomics; to_bytes re-emits
  all bindings. A GnuPG `--quick-add-uid` fixture guards the import.

### Changed (breaking)

- **Module renamed: `justinwongcn/openpgp` → `justinwongcn/moonpgp`**, and the
  flat layout replaced the `src/` layer. Import paths lose both the old module
  name and the intermediate directory:
  - `justinwongcn/openpgp/src/api` → `justinwongcn/moonpgp/api`
  - `justinwongcn/openpgp/src/mime` → `justinwongcn/moonpgp/mime`
  - `justinwongcn/openpgp/src/mail` → `justinwongcn/moonpgp/mail`
  - …and likewise for `primitives`, `armor`, `s2k`, `packet`, `cipher`, `pki`,
    `compress` and `interop`.
  Dependents must update `moon add justinwongcn/moonpgp` and every import path.
  The former `justinwongcn/openpgp@0.1.0` release is deprecated on mooncakes.io
  in favour of this module; no further versions will be published under it.
- `moon.mod` `repository` now points at `https://github.com/justinwongcn/moonpgp`.
- Documentation, CI and the interop scripts follow the new module name and the
  flat layout.

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
- **Self-implemented primitives** (`primitives`) — BLAKE2b (RFC 7693),
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
- **Email assembly** (`mail`) — RFC 5322 headers (Date, Message-ID,
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
