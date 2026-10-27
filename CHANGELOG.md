# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The module version lives in `moon.mod` (`version`); a section is only renamed to
a released version when that version is published to mooncakes.io.

## [Unreleased]

### Fixed — BZip2 truncated-stream crash (2026-10-28)

- A stream truncated mid-header crashed the process (out-of-bounds bit
  read) instead of raising: the 48-bit magic and 32-bit CRC reads in
  the decoder's wide bit reader skipped the bounds guard their narrow
  sibling has. Truncated input now raises the same malformed error.
  Found by the new hand-crafted malformed-bitstream tests.

### Added — test-completeness round (2026-10-28)

- 24 new tests pinning the extension features' failure modes, driven by
  a JEV review of what no existing test would catch: BZip2 malformed
  streams (stored block/stream CRC fields, randomized blocks, bad block
  magic and level digit, empty symbol map, bad group count, selector
  out of range and over budget, empty block, run overflow, invalid
  Huffman code — crafted bit for bit with a test-side bit writer),
  multi-User-ID expiry re-issuance, the v6 Direct Key signature stamp,
  explicit `created` stamps on every re-signing operation, locked-key
  refusals for the add-operations, the lifetime cap, v6 User ID
  revocation round-trips, primary-flag idempotency, and the
  cryptographic rejection of foreign-signed User ID revocations.
- `add_user_id` on an existing User ID now replaces its binding outright
  (the same last-certification-wins rule import applies), so a formerly
  revoked identity becomes usable again and the in-memory state matches
  what a round trip produces.
- `moon coverage analyze` uncovered-expression count for the three
  extension-round source files dropped from 41 to 13; the remainder are
  fail-closed guards reachable only with a fully forged multi-symbol
  Huffman table.

### Added — certificate extension round (2026-10-28)

- BZip2 decompression (RFC 9580 §9.4 algorithm 3) in pure MoonBit: the
  full block decode — symbol map, MTF-coded Huffman selectors, canonical
  Huffman, MTF/RLE2, inverse Burrows-Wheeler transform, leading run
  layer — with the block and stream CRCs verified on the way out. Mail
  that gpg emits under `--compress-algo bzip2` decrypts now; encoding
  stays ZIP/ZLIB-only and the output-side error says so explicitly.
  Live-verified against gpg 2.4.5 (`interop_gpg_bzip2_message.asc`).
- Subkey rotation for existing certificates: `add_encryption_subkey`
  (Curve25519Legacy ECDH on a v4 key, native X25519 on a v6 one) and
  `add_signing_subkey` (EdDSA legacy / native Ed25519, whose binding
  carries the cross-certification gpg requires).
- Expiry management: `set_expiry` re-issues every governing
  self-signature with a Key Expiration Time (0 clears it),
  `set_subkey_expiry` re-issues one binding by subkey id, and
  `KeyGenBuilder::expires` stamps the lifetime at generation time.
  gpg 2.4.5 shows the extended key with the exact requested expiry.
- User ID management: `add_user_id` certifies a new identity with the
  key's existing capability flags, `revoke_user_id` attaches a
  CertificationRevocation (reason 32, "User ID no longer valid") that
  survives export and re-import (gpg marks the identity `uid:r`),
  `set_primary_user_id` moves the Primary User ID flag, and
  `user_id()` now reports the flagged identity.
  `is_user_id_revoked` verifies the revocation cryptographically,
  lazily like key revocations. `UserIdBinding` gained a `revocation`
  field — a breaking change for external constructors, in line with the
  0.2.0 subkey-model change.
- gpg 2.4.5 live cross-checks (2026-10-28): it imports the extended
  certificates, signs through the added signing subkey (the
  cross-certification gate), encrypts to the added encryption subkey
  with moonpgp decrypting, lists the flagged User ID first, and marks
  the revoked one revoked.

### Added — open-source hygiene round (2026-10-28)

- SECURITY.md: supported versions, a private reporting channel via GitHub
  private vulnerability reporting, and an explicit end-of-life warning for
  0.1.0. Private vulnerability reporting is enabled on the repository, and
  a draft advisory covers the 0.1.0 subkey-injection flaw (fixed in 0.2.0).
- Release gate: the dispatchable **Release** workflow runs the full
  pipeline (fmt, strict check, build and test on all backends, smoke) and
  only then tags and publishes the GitHub Release, taking the notes from
  the CHANGELOG section of that version; `scripts/release_gate.sh` mirrors
  it locally. Released versions 0.2.0 and 0.3.0 got retroactive `v` tags
  and GitHub Releases.
- CONTRIBUTING.md, issue and pull-request templates, and the Contributor
  Covenant code of conduct.
- The README install sections (both languages) now ask for at least 0.2.0.

### Added — v6 dual-subkey generation and v6 subkey-revocation coverage (2026-10-26)

- `generate_ed25519_v6_key_with_signing_subkey` builds the gpg dual-subkey
  shape on a v6 certificate: a cert-only Ed25519 primary (self-signature
  key flags 0x01), an X25519 encryption subkey and an Ed25519 signing
  subkey whose v6 binding embeds a v6 Primary Key Binding
  (cross-certification, RFC 9580 §5.2.3.26 — a v6 key's self-signatures
  must be v6). With a cert-only primary, document signatures flow through
  the signing subkey, which makes the v6 embedded-signature branch (added
  with the R3 review fix) publicly reachable for the first time.
  `api/v6_signing_subkey_test.mbt` pins the shape end to end: flags, both
  bindings verifying, the embedded signature's v6 issuer fingerprint,
  signing-subkey issuer on detached signatures, and export/encryption
  round trips.
- v6 subkey revocation is covered too: `revoke_subkey` on a v6 key emits
  a version-6 SubkeyRevocation (no Issuer Key ID, the primary named by
  fingerprint in the hashed area), and the new test in
  `api/revocation_test.mbt` pins selection drop-out, decryption of mail
  that predates the revocation, and re-export survival.
- Interop boundary probed (2026-10-26): gpg 2.4.5 rejects v6 key and
  signature packets outright ("packet with unknown version 6"), so the
  gpg fixtures necessarily remain v4; v6 verification rests on the
  library's own cryptographic checks and round trips until a
  RFC 9580-capable GnuPG is available.

### Changed — performance: Argon2 permutation round in registers

- `argon2_round16` replaces the per-word `blamka_gb`/`argon2_round` pair:
  one P round now loads its 16 words into locals, runs the eight GB
  mixings with rotations inlined as shift-or (the old shape made ~640
  calls per 1 KiB block: 128 GB calls × 8 array round-trips plus a
  `rotr64` call per rotation), and stores back once. Math is unchanged —
  the RFC 9106 §5.3 KAT pass trace, the x/crypto vectors and the
  go-crypto 64 MiB S2K derive vectors all stay byte-identical. Measured
  for 64 MiB/t=3/p=4 on this machine (moon 0.1.20261023): native debug
  1.28s → 1.15s, native release 0.15s → 0.11s.
- **Stale baselines re-measured** (context for the 0.3.0-era notes): on
  the 2026-10-23 toolchain the core `BigInt::pow` is Montgomery with a
  4-bit window, and RSA-2048 keygen (`pki/bench_test.mbt`) measures
  0.9–1.9s wall including startup — the earlier ≈9.5s figure no longer
  reproduces, and with it the need to rework prime-candidate filtering.
  Argon2 64 MiB likewise measures 1.2–1.3s debug / 0.15s release before
  this change (the earlier ≈6.6s figure came from a different
  toolchain/machine state). Both recorded with the caveat that this
  machine's timings vary ~2× under background load; comparisons here
  were made by interleaving freshly built binaries.

## [0.3.0] - 2026-10-26

### Added / Changed — task 3 of the Jev-prioritized plan (2026-10-26)

- **v6 password shape in the encryption builder**: `.password_v6(pass)`
  adds a passphrase recipient as a v6 SKESK (AEAD + HKDF key separation)
  over a shared session key with a single v2 SEIPD payload — multiple
  passphrases get one SKESK each, options mirror
  `encrypt_with_password_v6` (`aead`, `argon2`, `passes`, `parallelism`,
  `memory_exp`; Argon2id by default). Mixing v4 (`.password`) and v6
  (`.password_v6`) shapes in one message is rejected. Under the hood
  `encrypt_with_password_v6` now delegates to the shared multi-recipient
  sealer (`seal_skesks_v6_with_passwords`).
- **Iterated S2K derivation streams instead of materializing** the
  ~54 MiB salt‖passphrase repetition: `primitives.hash_repetition` feeds
  the repetition through the streaming SHA-256/SHA-512/MD5/SHA-224/
  RIPEMD-160 forms (SHA-1/SHA-384 fall back to materializing). Measured
  on this machine: one 56 MB derivation 4s → ~1.8s, the two heaviest
  password tests 38.6s → 18.4s and 35.2s → 15.8s (≈2.2×); the remaining
  cost is the SHA-256 compression itself. RSA-2048 keygen (≈9.5s) and
  Argon2 64 MiB (≈6.6s) are bigint/BLAKE2-bound and unchanged — the
  recorded baselines for future optimization.

### Added — signing-subkey signing, closing the multi-subkey loop (2026-10-26, task 2b)

- Document signatures (`sign_detached` / `sign_inline` / `sign_and_encrypt`
  / `sign_cleartext*`) now choose their issuing component by certificate
  capability: a sign-capable primary keeps signing itself; a cert-only
  primary delegates to the last sign-capable bound subkey in wire order —
  the dual-subkey GnuPG shape this library can now both VERIFY (since N2)
  and PRODUCE. Certifications, bindings and revocations remain
  primary-issued (RFC 9580 §5.2.1). Revoked or expired primaries refuse
  to sign (their signatures would verify as rejected anyway).
- **Signing-subkey bindings embed the cross-certification** gpg requires:
  an Embedded Signature (subpacket 32) carrying the subkey's
  PrimaryKeyBinding (0x19) over the primary, carried in the unhashed area
  like gpg itself. Without it gpg refuses every signature from the subkey
  ("signing subkey is not cross-certified"). The PrimaryKeyBinding hash
  covers BOTH framed key packets (primary first) — the binding shape, not
  the direct-key shape; pinned empirically against gpg 2.4.5 and now by a
  fixture test that verifies gpg's own embedded signature.
- gpg 2.4.5 cross-verified in both directions: our subkey-issued detached
  signature imports and verifies as "Good signature", and we verify gpg's
  subkey-issued fixture signatures.
- `make_self_signature` gained a `key_flags` parameter (genuinely signed
  certify-only primaries, replacing in-memory flag surgery in tests).

### Added — revocation certificate generation (2026-10-26, task 2a of the Jev-prioritized plan)

- `revoke_key` / `revoke_subkey`: generate a primary-key (0x20) or subkey
  (0x28) revocation signature over the owner's key and return a revoked
  copy — every existing lifecycle gate (`is_revoked`, `can_encrypt`,
  `can_verify`, signature verification → `KeyRevoked`) sees it immediately,
  the revocation survives export/import, and decryption of pre-revocation
  mail keeps working.
- `generate_revocation_certificate`: the standalone armored `.rev` form
  (PUBLIC KEY BLOCK armor holding the signature, the shape gpg
  `--gen-revoke` emits); `PrivateKey::apply_revocation_certificate` /
  `PublicKey::apply_revocation_certificate` validate one cryptographically
  before applying — wrong-key or non-revocation certificates are rejected.
- `RevocationReason` (NoReason / Superseded / Compromised / Retired) with
  the reason + message subpacket (RFC 9580 §5.2.3.31).
- Cross-checked against gpg 2.4.5 in both directions during development:
  gpg imports our revoked certificate (marks the key revoked) and applies
  our standalone certificate; two interop tests pin gpg's own .rev file
  and a real gpg subkey-issued signature verifying as `KeyRevoked` after
  our subkey revocation.

### Fixed / Added — consolidation round (2026-10-26, task 1 of the Jev-prioritized plan)

- **Tag-20 AEAD containers decrypt on the private-key path** (found by the
  new GnuPG dual-subkey fixture): gpg 2.4 emits the 4880bis AEAD packet
  (tag 20) for recipients whose self-signature advertises the AEAD feature;
  `decrypt_with_private_key` / `decrypt_and_verify` used to recognize only
  SEIPD (tag 18). The ESK session key now opens the container directly,
  mirroring the password path's lenient GnuPG-interop handling.
- **Primary-key revocations survive re-export**: `PrivateKey::to_bytes` /
  `PublicKey::to_bytes` silently dropped `revocations`, so a round-tripped
  certificate lost its revocation status (`is_revoked` went back to false).
- **BZip2 honestly unsupported**: the old comment claimed "BZip2 is
  decode-only", which was never true — the registry's bzip2 package is a
  native libbz2 binding this pure-MoonBit library does not take. Comments
  and error messages now say "not implemented" in both directions, with
  regression tests.
- Real-GnuPG dual-subkey interop fixtures (Ed25519 cert-only primary +
  cv25519 encryption subkey + Ed25519 signing subkey; generation script
  `testdata/gen_gpg_dual_subkey_vectors.sh`): import keeps both subkeys, a
  signature issued by the signing subkey verifies, a gpg-encrypted message
  decrypts, and our encryption selects the encryption subkey — the
  multi-subkey model (N2) now has real-world data behind it.
- 12 targeted tests for coverage-report gaps: private import of a
  public-only bound subkey, same-UID re-certification (last wins),
  revocation packet attach/re-export, bare-v6 accessors, structural
  `encryption_key`, unlock no-op, wrong-passphrase error paths (cheap-S2K
  fixture), v6 password round-trip, literal-walk chains (OPS / algo-0 /
  ZIP), `verify_detached` armor shape errors, `NoVerifier` without a
  verifier, v6 session-key recovery.

## [0.2.0] - 2026-10-26

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
