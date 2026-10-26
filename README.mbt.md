# moonpgp

An OpenPGP library written in MoonBit: message encryption and decryption, signatures, key management, and PGP/MIME email.

**Module:** `justinwongcn/moonpgp` · [Package documentation](https://mooncakes.io/docs/justinwongcn/moonpgp)

[中文文档](./README.zh-CN.md)

## Install

You'll need the MoonBit toolchain; `moon` resolves dependencies for you.

```bash
moon add justinwongcn/moonpgp
```

The root package has the main API. Add `mime` and `mail` when you need PGP/MIME parsing or RFC 5322 message building:

```text
import {
  "justinwongcn/moonpgp",
  "justinwongcn/moonpgp/mime",
  "justinwongcn/moonpgp/mail",
}
```

The root package exposes its `@api` functions and option types as `@moonpgp.*`.

There's also a command-line demo, if you clone the repo:

```bash
git clone https://github.com/justinwongcn/moonpgp
cd moonpgp
moon run cmd/main -- help
```

## Features

- **Keys:** generate, import, export, lock and unlock with a passphrase. RSA, Ed25519 (legacy EdDSA), and Curve25519/X25519 are covered; new keys are v4, and v6 works too — `generate_ed25519_v6_key_with_signing_subkey` produces the gpg dual-subkey shape on v6: a cert-only primary, an X25519 encryption subkey and an Ed25519 signing subkey carrying the v6 cross-certification. All bound subkeys are kept, each judged by its own key flags, and helpers check capabilities, expiry, and revocation. You can also revoke a key or a single subkey, and issue a standalone `.rev` certificate to apply later — gpg's `--gen-revoke` certificates apply too.
- **Messages:** public-key or passphrase encryption, detached/inline/cleartext signatures, session-key operations, optional ZIP/ZLIB compression. Document signatures come from the primary key when it may sign, otherwise from a signing subkey (its binding carries the cross-certification gpg requires). Anything this library encrypts uses AES; CAST5 and 3DES exist for decryption only.
- **v6 messages:** v6 PKESK/SKESK and v2 SEIPD with OCB, EAX, or GCM AEAD, end to end. In the encryption builder, `.password_v6` adds a v6 passphrase recipient; v4 and v6 shapes don't mix in one message. Regular v4 recipient and passphrase flows default to v1 SEIPD.
- **Passphrase protection:** iterated-and-salted S2K and Argon2, including the AEAD-protected secret-key formats.
- **Email:** `mime` parses and verifies PGP/MIME; `mail` builds RFC 5322 messages, signed and encrypted PGP/MIME included. The SMTP/IMAP clients under `example/` are examples rather than library API, and they only run on native.

## Interop and local checks

Tests include some interop with GnuPG, OpenSSL, and go-crypto, plus RFC test vectors. The GnuPG checks live in [`scripts/interop_check.sh`](./scripts/interop_check.sh).

Locally:

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native
moon fmt --check
```

CI covers native, wasm, and js; for day-to-day work, use native. Key generation and anything else that depends on randomness needs a platform entropy source, which not every runtime provides.

## Security and limitations

- Import verifies the signatures it understands (User ID certifications, subkey bindings, v6 direct-key signatures), but that's signature checking, not trust management: whether a key really belongs to someone is for your application to decide.
- RSA, Ed25519, and X25519 arithmetic runs on `@bigint` and is not constant-time, and a GC runtime makes no promise about wiping private keys from memory.
- Decrypting untrusted Argon2-protected data is capped at 64 MiB of memory by default; over-limit requests are rejected before anything is allocated. Some APIs let you set a different limit.
- The encryption APIs don't pad v2 SEIPD messages, so ciphertext length gives away roughly how long the plaintext is.
- On targets without a platform clock, expiration checks are off and revocation dates can't be evaluated; revocation signatures are still checked cryptographically.

Dependency and attribution details are in [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md).

## License

Apache-2.0. See [LICENSE](./LICENSE), [NOTICE](./NOTICE), and [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).
