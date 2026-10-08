# moonpgp — OpenPGP email encryption in pure MoonBit

An OpenPGP (RFC 4880/9580) email encryption, decryption, signing,
verification and sending library implemented from scratch in MoonBit,
matching the core capabilities of ProtonMail gopenpgp v3 — including
PGP/MIME (RFC 3156) composition/parsing and end-to-end signed+encrypted
mail submission. Built for the October MoonBit hackathon.

中文文档：[README.zh-CN.md](./README.zh-CN.md)

## Installation

**Requirements.** MoonBit toolchain `moon 0.1.20260920` / `moonc
v0.10.14+7d59c7ec9` (moonc 0.10.14 or newer). No C toolchain, no FFI, no
vendored code: the library is pure MoonBit and depends only on
`moonbitlang/x`, `moonbitlang/async` and `moonbit-community/flate`, which
`moon` resolves automatically. The library target is `native` (see
`preferred_target` in `moon.mod`).

**Add it to an existing MoonBit project:**

```bash
moon add justinwongcn/openpgp
```

Then declare the packages you need in that project's `moon.pkg`:

```text
import {
  "justinwongcn/openpgp/src/api",
  "justinwongcn/openpgp/src/mime",   // PGP/MIME (RFC 3156) parsing/verification
  "justinwongcn/openpgp/src/mail",   // RFC 5322 / MIME assembly
}
```

**Use the CLI without writing any code** — run it straight from a clone of
this repository:

```bash
git clone https://github.com/justinwongcn/openpgp
cd openpgp
moon run cmd/main -- help
```

**Build and test a clone** (the exact commands CI runs):

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native      # 347 tests
moon fmt --check
```

## Features (P0 + P1 + email pipeline + mail sending complete)

| Domain | What's implemented |
|---|---|
| ASCII Armor | CRC-24 checksum, multi-block parsing, CRLF tolerance |
| Packet engine | RFC 9580 packet headers (old/new formats, partial lengths), PKESK v3+v6, SKESK v4/v5/v6, PublicKey/SecretKey/SecretSubkey (v4+v6), UserID, Signature v4+v6 (subpacket parsing), OnePassSig v3+v6, Literal, Padding, Compressed, SEIPD v1+MDC and v2 |
| Symmetric encryption | AES-128/192/256, OpenPGP-CFB (both the resync and no-resync variants), MDC integrity protection, and the **v2 SEIPD chunked-AEAD layer** (salt + HKDF message key/IV, `0xD2` header, per-chunk AD, final length-bound tag) |
| S2K | Simple / Salted / Iterated+Salted (SHA-256/SHA-1/RIPEMD-160/MD5) and **Argon2 (type 4, RFC 9580 §3.7.1.4)** |
| Argon2 primitives | Self-implemented **BLAKE2b** (RFC 7693), **Argon2id** (RFC 9106, v=0x13) and **HKDF-SHA256** (RFC 5869) in `src/primitives`, with an explicit memory cap before allocating |
| RSA | PKCS#1 v1.5 encryption, signing, verification; key generation (Miller-Rabin, CRT, extended-Euclid modular inverse) |
| Ed25519 | EdDSA legacy (algorithm 22) signing/verification and key generation (self-implemented on `@bigint`, `pki/ed25519.mbt`) |
| ECDH / X25519 | **X25519 v6 (algorithm 25)** native-key wrap/unwrap: HKDF-SHA256 with `info = "OpenPGP X25519"` + AES-128 Key Wrap, v6 PKESK by fingerprint; Curve25519Legacy (algorithm 18) X25519 + SHA-256 KDF (§11.4) + AES Key Wrap (RFC 3394) with the PKESK v3 ephemeral-point format |
| Key management | Transferable-key assembly/parsing, creation and verification of self-signatures and subkey binding signatures, passphrase locking/unlocking (usage 254 CFB, and **usage 253 AEAD + HKDF** with Argon2id or iterated S2K), armored import/export, keyring |
| AEAD modes | OCB (RFC 7253, MTI), EAX and GCM (RFC 9580 §5.13.3–5.13.5), all three usable for v2 SEIPD, v5/v6 SKESK and usage-253 secret keys |
| Compression | Compressed packet: ZIP (raw DEFLATE) / ZLIB / uncompressed; the decompressor fully supports dynamic Huffman |
| MIME | PGP/MIME (RFC 3156): multipart/signed construction + verification, multipart/encrypted parsing, RFC 5322 header parsing; email pipeline aligned with gopenpgp v3 `mime/`: Content-Type parameter parsing, Content-Transfer-Encoding decoding (base64/quoted-printable), byte-exact MIME tree parsing, body/attachment collection (gomime semantics), one-shot `decrypt_mime` with callback delivery and gopenpgp signature-status merge (Ok/NotSigned/NoVerifier/Failed) |
| Email assembly (library) | `src/mail`: RFC 5322 headers (Date/Message-ID/atext-quoting addresses, RFC 2047 encoded words), multipart/mixed with the RFC 3156 §3 7-bit strategy (ASCII→7bit / non-ASCII→QP / attachments base64), generalized multipart/signed over pre-built entities, one-shot `build_encrypted_mail` — the composing half of PGP/MIME, symmetric with `src/mime` parsing |
| v6 message encryption | v6 PKESK + **v2 SEIPD** for v6 X25519 subkeys, v6 SKESK + v2 SEIPD for passphrases, honoring the recipient's Preferred AEAD Ciphersuites; `generate_ed25519_v6_key` now emits the X25519 encryption subkey with a v6 binding signature |
| Top-level API | `pgp().encryption()/decryption()/key_generation()` builders, KeyRing |

## Interoperability (all verified by real cross-testing)

- **GnuPG 2.4.5, both directions**:
  - we decrypt what `gpg --symmetric` produces; gpg decrypts what we produce;
  - our RSA keys import into gpg (primary [SC] + subkey [E]); gpg encrypts to them and we decrypt; we encrypt and gpg decrypts;
  - **Ed25519 (EdDSA legacy), both directions**: gpg verifies our Ed25519 signatures with `Good signature` and recognizes our Ed25519+cv25519 key as `pub ed25519 [SC] / sub cv25519 [E]`; we verify gpg's Ed25519 signatures (detached + cleartext, SHA-512);
  - **ECDH (Curve25519Legacy), both directions**: we decrypt what gpg encrypts to our cv25519 subkey; gpg decrypts (reporting `encrypted with cv25519 key`) what we encrypt to its cv25519 subkey (X25519 + SHA-256 KDF + RFC 3394 key wrap);
  - **MIME, full pipeline**: gpg-encrypted multipart/signed mail (gpg signature over the exact part bytes) decrypts, tree-walks and verifies Ok through `decrypt_mime`; a tampered inner body is reported as `Failed`; `gpg --encrypt --sign` over a multipart/mixed text verifies its embedded signature and delivers body + attachment (vectors in `testdata/interop_gpg_mime_*`, regenerated by `testdata/gen_gpg_mime_vectors.sh`);
  - **mail sending, end-to-end** (`example/mailer/e2e.sh`): a composed mail (body + attachment, signed then encrypted per RFC 3156 §6.1) is submitted over a real SMTP socket, then gpg decrypts it and verifies the inner signature (`Good signature`); payloads are compared byte-exactly, and our own `decrypt_mime` re-verifies the roundtrip;
  - gpg verifies our RSA/Ed25519 signatures (Good signature); we verify gpg's signatures.
- **openssl 3.x**: RSA-2048 signatures reproduced byte-for-byte; ciphertexts produced by openssl decrypt correctly.
- **ProtonMail gopenpgp testdata**: unlocking an OpenPGP.js private key (passphrase "apple"), decrypting `message_signed` → `message_plaintext`, verifying its v4 self-signature, parsing a GPG smartcard dummy key.
- **go-crypto v1.4.1 (the version gopenpgp v3 pins)**: we unlock go-crypto-written v4 **and** v6 secret keys protected with Argon2id + AES-256/OCB + HKDF (usage 253), decrypt a go-crypto-written Argon2 S2K message, and decrypt go-crypto's **v6 PKESK + v2 SEIPD** and **v6 SKESK + v2 SEIPD** messages (fixtures + generator in `testdata/gen_gocrypto_argon2_vectors.md`). In the other direction a go-crypto harness unlocks our Argon2-locked v4/v6 keys, decrypts our v4/v6 Argon2 S2K messages, our v6 PKESK+v2 SEIPD and v6 SKESK+v2 SEIPD messages, and verifies our v6 inline signature.
- **RFC 9580 Appendix A.8–A.11**: the four complete v6 message sequences (X25519 + AEAD-OCB, AEAD-EAX, AEAD-OCB, AEAD-GCM) decrypt to "Hello, world!", together with A.4 (unprotected v6 key) and the per-chunk intermediate values; `src/cipher/seipd_v2_test.mbt` also checks the A.8/A.9/A.10 HKDF outputs octet for octet.
- **RFC 4493 CMAC / RFC 9106 §5.3 / RFC 7693 / RFC 5869**: known-answer tests for every new primitive, including Argon2 memory sizes that are not a multiple of `4*parallelism` and tag lengths above 64 octets.
- **RFC 9580 Appendix A.12/A.5**: the three A.12 SKESK messages (AES-128/192/256, Argon2 t=1 p=4 m=2^21) decrypt to "Hello, world!", and the A.5 v6 Ed25519 key unlocks with its passphrase and signs. Both are 2 GiB Argon2 derivations, so they are `#skip`ped by default and run with `moon test src/api --target native --include-skipped --filter 'slow:*'`.
- **RFC 9106 / RFC 7693 / RFC 5869 known-answer tests**: the Argon2id KAT including secret and associated data, the x/crypto vector table, all BLAKE2b reference vectors, and the three HKDF Appendix A cases.
- Known-answer vectors: SEIPD v1 produced by openssl AES-CFB; AES Key Wrap against the official RFC 3394 Appendix B vectors.

One command runs the full GnuPG interop matrix (six directions, a freshly
generated key every run):

```bash
./scripts/interop_check.sh
```

Automated tests: `moon test --target native` (347 tests covering all vectors
above; two RFC 9580 Argon2 fixtures are `#skip`ped because each derivation
needs 2 GiB — run them with `--include-skipped --filter 'slow:*'`).
`moon test --target wasm` and `--target js` run 339 tests. wasm-gc has no
platform entropy source: its entropy-free subset still passes, but the 100
tests that generate key material (keygen, random IV/salt, Argon2) fail there
with `platform entropy source unavailable`; use native, wasm or js for the
full suite.

## Quick start (CLI demo)

```bash
moon run cmd/main -- keygen "Demo <demo@example.com>" sec.asc pub.asc      # RSA key (default 3072 bits)
moon run cmd/main -- edkeygen "Demo <demo@example.com>" sec.asc pub.asc    # Ed25519 + cv25519 key
moon run cmd/main -- encpass "passphrase" plain.txt msg.asc                # passphrase encrypt
moon run cmd/main -- decpass "passphrase" msg.asc restored.txt             # passphrase decrypt
moon run cmd/main -- encpub pub.asc plain.txt msg2.asc                     # public-key encrypt (RSA/ECDH auto)
moon run cmd/main -- decpriv sec.asc msg2.asc restored2.txt                # private-key decrypt
moon run cmd/main -- sign sec.asc plain.txt sig.asc                        # detached signature
moon run cmd/main -- verify pub.asc plain.txt sig.asc                      # verify
```

## Library usage

```moonbit nocheck
// passphrase encrypt/decrypt

///|
let armored = @api.encrypt_with_password(plaintext, "passphrase")

///|
let plain = @api.decrypt_with_password(armored, "passphrase")

// key generation + public-key encrypt / private-key decrypt

///|
let key = @api.generate_key("Alice <alice@example.com>")

///|
let armored = @api.encrypt_to_recipients(data, [key.to_public()])

///|
let plain = @api.decrypt_with_private_key(armored, key)

// gopenpgp-style builders

///|
let encrypt = @api.pgp().encryption().password("pw").finish()

///|
let decrypt = @api.pgp().decryption().password("pw").finish()
```

### Email demo pipeline (`example/`, not part of the library API)

The library's email scope is **assembly (`src/mail`) + parsing/verification
(`src/mime`)**. The wire transports — a POSIX-socket SMTP client, an
IMAP4rev1 subset client (`example/netmail`) and the two CLI demos
(`example/mailer`, `example/mailreader`) — are **demo and test
infrastructure**, not published API: they exist to prove the library
end-to-end (a signed+encrypted mail is composed, submitted via msmtp,
fetched back over IMAP, decrypted and verified in one loop —
`example/mailer/e2e.sh`, `example/mailreader/e2e.sh`).

They are functional (used for the real-internet round trip against a 163
mailbox and a Proton peer) but carry deliberate limitations: native
target only (TLS submission rides the POSIX socket with a blocking
facade over `moonbitlang/async/tls`), implicit TLS (465) and STARTTLS
(587) supported with system-root or pinned-certificate trust, INBOX-only
IMAP, plaintext to non-local hosts refused unless explicitly opted in.
See Security notes.

## Module layout (designed for replaceability)

```
src/
├── primitives/  # isolation layer: the only third-party crypto entry point; BlockCipher trait, HashId, asserted entropy
├── armor/       # CRC-24 + armor (PGP-specific, never replaced)
├── s2k/         # S2K (PGP-specific, never replaced)
├── packet/      # packet format engine (PGP-specific, never replaced)
├── cipher/      # OpenPGP-CFB variants + SEIPD v1/MDC + AES Key Wrap (RFC 3394)
├── pki/         # RSA (keygen/PKCS#1 v1.5), Ed25519/X25519 (self-implemented per RFC 8032/7748, `curve25519.mbt`)
├── compress/    # DEFLATE/ZLIB (currently moonbit-community/flate, replaceable)
├── mime/        # PGP/MIME (RFC 3156), MIME tree parsing/collectors, transfer-encoding decoding
├── mail/        # RFC 5322 mail assembly (headers, QP/7bit strategy, attachments) — no transport
├── api/         # key management, signing, ECDH/RSA session-key wrapping, keyring, builders
└── interop/     # interop tests against gopenpgp/GnuPG/openssl
```

Wire transports and the CLI demos live under `example/` (netmail, mailer,
mailreader) as demo/test infrastructure — see "Email demo pipeline" above.

## Dependencies (version-pinned)

`moonbitlang/x@0.5.5` (hash suite/HMAC/AES-ECB block primitive) and
`moonbit-community/flate@0.8.4` (DEFLATE). Ed25519/X25519 are self-implemented
per RFC 8032/7748 on core `@bigint` (`pki/curve25519.mbt`) — no third-party
public-key dependency. Swapping any of these means rewriting one adapter file
in `primitives` (or the relevant module) plus a full vector regression.

See [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md) for the complete list
of third-party dependencies and test-vector provenance (including the gopenpgp
MIT attribution).

## Security notes (honest disclosure)

- All key/session-key/prime randomness comes from the platform entropy source
  asserted via `@env.rand` — **no fixed-seed fallback**.
- RSA key generation uses 40-round random-base Miller-Rabin plus small-prime
  trial division; 3072-bit by default.
- The `@bigint` field arithmetic behind Ed25519/X25519 is **not constant-time**
  (same class of limitation as RSA). For high-value scenarios that require
  timing-side-channel resistance, swap in a constant-time implementation
  (`pki/curve25519.mbt` is the isolation point).
- GC languages cannot truly wipe private key memory; `Cipher::wipe`/key
  zeroing is best-effort.
- Limited support for legacy v3 features on the decryption side; the
  generation side emits v4 packets by default. RFC 9580 v6 Ed25519
  signing keys/signatures and the AEAD (OCB/GCM) message shapes are
  implemented (v6: detached signatures only; AEAD: symkey/tag-20 for
  GnuPG `--force-aead` interop — new keys still use SEIPD v1). Argon2 S2K
  (type 4), the usage-253 secret-key protection (Argon2 + HKDF-SHA256 +
  AES-256/OCB), v6 PKESK/SKESK and v2 SEIPD message encryption are all
  implemented; Ed448/X448 and v5 keys remain out of scope.
- **No hidden-length padding**: the Padding packet (tag 21) is parsed and
  skipped on decryption (the RFC 9580 appendix samples use it), but
  `encrypt_to_recipients` / `encrypt_with_password_v6` do not add it, so a
  v2 SEIPD message reveals its approximate length.
- **Argon2 memory is attacker-controlled**: a 20-octet S2K specifier can
  ask for up to 2^31 KiB, and the derivation runs before any
  authentication. Entry points that parse untrusted packets
  (`decrypt_with_password`, `decrypt_binary_with_password`,
  `PrivateKey::unlock`) therefore default to
  `DEFAULT_ARGON2_MAX_MEMORY_KIB` = 256 MiB and refuse an oversized request
  **before allocating** — 4x the 64 MiB profile every mainstream writer
  emits, 8x below the implementation ceiling `ARGON2_MAX_MEMORY_KIB`
  (2 GiB, RFC 9106's first recommended option, used by RFC 9580 Appendix
  A.5/A.12). Opening such a message needs the wider policy explicitly:
  `decrypt_with_password(msg, pass, argon2_max_memory_kib=@primitives.ARGON2_MAX_MEMORY_KIB)`,
  which is what `scripts/acceptance.sh` does for those RFC vectors. For
  scale: OpenPGP.js defaults its cap to 1 TiB and go-crypto/gopenpgp impose
  none.
- **No certificate / self-signature validation**: key parsing is
  structural only. A v6 key must *carry* a Direct Key signature
  (RFC 9580 §5.2.3.10) but it is **not** cryptographically verified, and
  algorithm preferences, expiry and revocation are read from the signature
  as given. This matches gopenpgp/go-crypto, the reference this library
  targets (which also selects self-signatures without verifying them);
  applications that need trust must verify keys themselves — cf.
  `gpg --check-sigs`, OpenPGP.js `verifyPrimaryKey`, Sequoia
  `Cert::with_policy`.
- Non-native backends (wasm/js) have no clock API yet; key creation timestamps
  are placeholders (see `primitives/clock.mbt`).
- The demo transports (`example/netmail`) are **native-only**. SMTP
  submission is encrypted by default (implicit TLS on 465 / STARTTLS on
  587, verified against the OS root store); `--smtp-trust pem:FILE`
  pins the peer certificate (exact DER match), and `--smtp-trust none`
  is opt-in only with a loud warning. AUTH PLAIN over plaintext is
  still refused to non-localhost hosts, and IMAP plaintext to non-local
  hosts requires an explicit `allow_insecure` opt-in. Plaintext-only
  flows (no TLS terminator available) can hand .eml to an MTA (msmtp).
  Plaintext exposure is limited to credentials and metadata — message
  content stays end-to-end encrypted.

## Roadmap

- P1 complete: ✅ cleartext signing (gpg cross-verified), ✅ PGP/MIME (RFC 3156
  construction/parsing, gpg cross-verified), ✅ DEFLATE, ✅ Ed25519
  (sign/verify/keygen, bidirectional gpg interop), ✅ ECDH Curve25519Legacy
  encryption side (X25519 + KDF + key wrap, bidirectional gpg interop).
- Email pipeline (2026-10-02): gopenpgp v3 `mime/`-aligned decrypt_mime +
  MIME tree/collectors + Content-Type/CTE decoding, gpg cross-verified.
- Mail sending (2026-10-02): `src/mail` composition + `example/mailer`
  SMTP/file transports, gpg-verified end-to-end. TLS submission
  (2026-10-06): implicit TLS/STARTTLS via `moonbitlang/async/tls`,
  gpg-verified end-to-end against a local TLS sink
  (`example/mailer/e2e_tls.sh`); msmtp is now the fallback, not a
  requirement.
- v6 + AEAD (2026-10-08): RFC 9580 v6 Ed25519 detached signatures and
  v6 key packets/fingerprints (cross-checked against go-crypto v1.4.1 and
  the mizchi `pgp` reference package), plus self-written OCB3 (RFC 7253)
  and GCM with the 4880bis tag-20 chunk layer and v5 SKESK
  (`encpass ... aead`), byte-level gpg `--force-aead` interop in both
  directions (`scripts/interop_aead_gpg.sh`).
- Argon2 S2K (2026-10-08): self-implemented BLAKE2b (RFC 7693), Argon2id
  (RFC 9106) and HKDF-SHA256 (RFC 5869); S2K specifier type 4; the
  usage-253 secret-key protection path (HKDF key separation + AES-256/OCB +
  public-key-associated data); `PrivateKey::lock_argon2` / `unlock`, and
  `encrypt_with_password_argon2`. Verified against RFC 9106 §5.3, the
  x/crypto vector table, RFC 9580 Appendix A.12/A.5, and go-crypto v1.4.1
  in both directions.
- v6 message encryption (2026-10-08): v6 PKESK (§5.1.2) with X25519 key
  wrap, v6 SKESK (§5.3.2) with HKDF key separation, v2 SEIPD (§5.13.2)
  chunked AEAD, v6 X25519 encryption subkeys with v6 binding signatures,
  v6 One-Pass Signatures, the Features / Preferred AEAD Ciphersuites
  subpackets, and EAX (RFC 9580 §5.13.3). Verified against RFC 9580
  Appendix A.8 (X25519+OCB), A.9 (EAX), A.10 (OCB) and A.11 (GCM), plus
  go-crypto v1.4.1 differentials in both directions.
- Post-contest roadmap: Ed448/X448 and v5 key support, hidden-recipient
  v6 PKESK, self-implemented DEFLATE (replacing moonbit-community/flate,
  differential-testing plan).

New capabilities (P1):

```moonbit nocheck
// cleartext signing (RFC 9580 §7)
let msg = @api.sign_cleartext("text\n", key)
let (text, status) = @api.verify_cleartext(msg, key.to_public())

// PGP/MIME (RFC 3156)
let mime_msg = @mime.build_pgp_mime_signed("body\n", key)
let (text, status) = @mime.verify_pgp_mime_signed(mime_msg, key.to_public())
let payload = @mime.extract_pgp_encrypted(mime_msg)   // extract the PGP MESSAGE

// Ed25519 primary key (EdDSA legacy, algorithm 22) + Curve25519Legacy ECDH
// encryption subkey — the gopenpgp "Default" profile shape, verified live
// against gpg in both directions
let key = @api.generate_ed25519_key("Ed <ed@example.com>")

// Argon2 S2K (RFC 9580 §3.7.1.4, specifier type 4) — the RFC's recommended
// passphrase KDF, in the gopenpgp RFC 9580 profile's default shape
// (t=3, p=4, m=2^16 KiB); unlock() handles usage 253 and 254 alike.
let locked = key.lock_argon2("passphrase", memory_exp=16)
let unlocked = locked.unlock("passphrase")
let msg = @api.encrypt_with_password_argon2(plaintext, "passphrase")
let back = @api.decrypt_with_password(msg, "passphrase")

// Email (MIME) support aligned with gopenpgp v3's mime/ domain:
// decrypt an armored PGP mail, walk the MIME tree, verify a root
// multipart/signed and deliver body + attachments via callbacks
// (gpg cross-verified end-to-end; charset support is UTF-8/lossy).
let recorder = ...  // any value implementing @mime.MimeCallbacks
@mime.decrypt_mime(
  armored_mail,                     // armored PGP message (RFC 3156 payload)
  [private_key],
  verifiers=[signer_public_key],
  callbacks=recorder,               // on_body / on_attachment / on_verified / on_error
)

// Building blocks are public too: Content-Type parameter parsing,
// Content-Transfer-Encoding decoding (base64/quoted-printable), and a
// byte-exact MIME tree parser with a gomime-compatible collector.
let root = @mime.parse_mime_tree(payload_bytes)
let (body, attachments) = @mime.collect_body_and_attachments(root)

// One-shot mail composition (RFC 3156 §6.1: sign then encrypt) — run
// `./example/mailer/e2e.sh` for the gpg-verified end-to-end demo.
let mail = @mail.build_encrypted_mail(
  from, to,
  subject=..., text=..., attachments=...,
  signer=private_key, recipients=[public_key],
  domain="mailpgp.example",
)
```
