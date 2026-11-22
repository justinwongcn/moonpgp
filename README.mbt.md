# moonpgp

An OpenPGP library written in MoonBit: message encryption and decryption, signatures, key management, and PGP/MIME email.

**Module:** `justinwongcn/moonpgp` · [Package documentation](https://mooncakes.io/docs/justinwongcn/moonpgp) · [![CI](https://github.com/justinwongcn/moonpgp/actions/workflows/ci.yml/badge.svg)](https://github.com/justinwongcn/moonpgp/actions/workflows/ci.yml)

[中文文档](./README.zh-CN.md)

## Install

You'll need the MoonBit toolchain; `moon` resolves dependencies for you.

```bash
moon add justinwongcn/moonpgp
```

Use 0.2.0 or later: the 0.1.0 release is affected by a known subkey-injection flaw (see [SECURITY.md](SECURITY.md)). A fresh `moon add` resolves the newest release.

The root package has the main API. Add `mime` and `mail` when you need PGP/MIME parsing or RFC 5322 message building:

```text
import {
  "justinwongcn/moonpgp",
  "justinwongcn/moonpgp/mime",
  "justinwongcn/moonpgp/mail",
}
```

The root package exposes its `@api` functions and option types as `@moonpgp.*`.

## A taste of the API

Generate a key, encrypt to it, open the message again. This block is
type-checked and run by `moon test`, so it cannot drift from the code:

```mbt check
///|
test "a tiny round trip" {
  let key = @moonpgp.generate_ed25519_key("alice@example.com")
  let armored = @moonpgp.pgp().encryption().recipient(key.to_public()).finish()(
    b"hi, from the README",
  )
  let open = @moonpgp.pgp().decryption().decryption_key(key).finish()
  match open(armored) {
    Data(data) => assert_eq(data, b"hi, from the README")
    Verified(data) => assert_eq(data, b"hi, from the README")
    SignatureError(_) => fail("unexpected signature error")
  }
}
```

Failures are typed: a wrong passphrase raises `WrongPassphrase`, unparsable
input `Malformed`, an unimplemented algorithm `Unsupported` — all reachable
from the bare root import:

```mbt check
///|
test "wrong passphrases are a typed error" {
  let key = @moonpgp.generate_ed25519_key("alice@example.com").lock("right")
  try {
    let _ = key.unlock("wrong")
    fail("unlocking must fail")
  } catch {
    @moonpgp.PgpError::WrongPassphrase(_) => () // the expected failure class
    _ => fail("expected WrongPassphrase")
  }
}
```

Sign data and verify detached signatures:

```mbt check
///|
test "detached signatures and verification" {
  let signer = @moonpgp.generate_ed25519_key("signer@example.com")
  let data = b"release tarball bytes or document payload"
  let sig = @moonpgp.sign_detached(data, signer)
  let status = @moonpgp.verify_detached(data, sig, signer.to_public())
  assert_eq(status, @moonpgp.VerifyStatus::Ok)
}
```

For PGP/MIME emails, import `"justinwongcn/moonpgp/mime"`:

```mbt check
///|
test "pgp/mime sign and verify" {
  let key = @moonpgp.generate_ed25519_key("mime@example.com")
  let message = @mime.build_pgp_mime_signed("Hello from MoonBit\n", key)
  let (_, status) = @mime.verify_pgp_mime_signed(message, key.to_public())
  assert_eq(status, @api.Ok)
}
```

There's also a command-line demo, if you clone the repo:

```bash
git clone https://github.com/justinwongcn/moonpgp
cd moonpgp
moon run cmd/main -- help
```

## Features

- **Keys:** generate, import, export, lock and unlock with a passphrase. RSA, Ed25519 (legacy EdDSA), and Curve25519/X25519 are covered; new keys are v4, and v6 works too — `generate_ed25519_v6_key_with_signing_subkey` produces the gpg dual-subkey shape on v6: a cert-only primary, an X25519 encryption subkey and an Ed25519 signing subkey carrying the v6 cross-certification. All bound subkeys are kept, each judged by its own key flags, and helpers check capabilities, expiry, and revocation. Certificates also grow and change in place: revoke a key or a single subkey, issue a standalone `.rev` certificate (gpg's `--gen-revoke` certificates apply too), add fresh encryption or signing subkeys to an existing key, set or extend expiry at generation time (`KeyGenBuilder::expires`) or later (`set_expiry`, `set_subkey_expiry`), and manage identities with `add_user_id`, `revoke_user_id` and `set_primary_user_id`.
- **Messages:** public-key or passphrase encryption, detached/inline/cleartext signatures, session-key operations, ZIP/ZLIB compression on output. On input, BZip2-compressed messages decrypt as well — the format gpg emits under `--compress-algo bzip2` — through a pure-MoonBit codec that verifies every block and stream CRC. Document signatures come from the primary key when it may sign, otherwise from a signing subkey (its binding carries the cross-certification gpg requires). Anything this library encrypts uses AES; CAST5 and 3DES exist for decryption only.
- **v6 messages:** v6 PKESK/SKESK and v2 SEIPD with OCB, EAX, or GCM AEAD, end to end. In the encryption builder, `.password_v6` adds a v6 passphrase recipient; v4 and v6 shapes don't mix in one message. Regular v4 recipient and passphrase flows default to v1 SEIPD.
- **Passphrase protection:** iterated-and-salted S2K and Argon2, including the AEAD-protected secret-key formats.
- **Email:** `mime` parses and verifies PGP/MIME; `mail` builds RFC 5322 messages, signed and encrypted PGP/MIME included. The SMTP/IMAP clients under `example/` are examples rather than library API, and they only run on native.

## Interop and local checks

Tests include some interop with GnuPG, OpenSSL, and go-crypto, plus RFC test vectors. The GnuPG checks live in [`scripts/interop_check.sh`](./scripts/interop_check.sh) and run on a nightly CI schedule (plus frozen GnuPG-produced vectors in the per-push suite).

Locally:

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native
moon fmt --check
```

CI covers native, wasm, and js; for day-to-day work, use native. Key generation and anything else that depends on randomness needs a platform entropy source, which not every runtime provides.

## Security and limitations

- The OpenPGP ecosystem is bigger than this library: keyserver lookup and sync, Web of Trust, smartcards and other hardware tokens, Autocrypt, designated revokers, signature notation data, and the Ed448/X448 algorithms are not implemented, and neither is reading the legacy unauthenticated SED packet (RFC 9580 §5.14 — refused on input). If your application needs those, this is the wrong layer to ask.
- Import verifies the signatures it understands (User ID certifications, subkey bindings, v6 direct-key signatures), but that's signature checking, not trust management: whether a key really belongs to someone is for your application to decide.
- RSA, Ed25519, and X25519 arithmetic runs on `@bigint` and is not constant-time, and a GC runtime makes no promise about wiping private keys from memory.
- Decrypting untrusted Argon2-protected data is capped at 64 MiB of memory by default; over-limit requests are rejected before anything is allocated. Some APIs let you set a different limit.
- One message can only ask for so much key derivation: each SKESK attempt books its KDF work against a shared per-message budget — roughly three saturated Argon2 derivations, or about six gpg-default iterated ones — and once the line is crossed, further attempts are rejected explicitly before any work is spent.
- Verification refuses MD5 outright, and refuses SHA-1 and RIPEMD-160 for anything recent — created after 2020-01-01 (SHAttered) or carrying no creation time at all (RFC 9580 §9.5; gpg behaves the same). Signatures from before the cutoff still verify for legacy mail. Signing refuses MD5, SHA-1, and RIPEMD-160 on its side.
- RSA key generation requires 3072 bits or more (RFC 9580 §12.4) and caps at 16384 (OpenSSH's limit; larger moduli mean hours of pure-bigint primality work). RSA below 2048 bits is refused for encryption, signing, and verification (§12.4's MUST line); decryption with smaller legacy keys still works. Expect ~10 s per 3072-bit key: the arithmetic runs on this project's own pure-MoonBit bigint rather than a native bignum like GMP, which is what makes GnuPG keygen sub-second. For new keys prefer Ed25519/X25519 (`generate_ed25519_key`, instant) — the same default the wider industry moved to; prime caching across keys is a hard no (prime reuse is a catastrophic flaw), so there is no shortcut to trade away.

- Exporting an unlocked private key is an explicit `allow_unlocked: true` decision; locked keys export as usual. Debug formatting of key material is redacted to lengths.
- PGP/MIME delivers the body in the canonicalized form the signature was verified over; binary attachments stay byte-exact.
- The encryption APIs don't pad v2 SEIPD messages, so ciphertext length gives away roughly how long the plaintext is.
- On targets without a platform clock, expiration checks are off and revocation dates can't be evaluated; revocation signatures are still checked cryptographically.

Dependency and attribution details are in [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md).

## License

Apache-2.0. See [LICENSE](./LICENSE), [NOTICE](./NOTICE), and [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).
