# moonpgp

An OpenPGP library written in MoonBit for message encryption and decryption, signatures, key management, and PGP/MIME email workflows.

**Module:** `justinwongcn/moonpgp` · [Package documentation](https://mooncakes.io/docs/justinwongcn/moonpgp)

[中文文档](./README.zh-CN.md)

## Install

Requires the MoonBit toolchain. Dependencies are resolved by `moon`.

```bash
moon add justinwongcn/moonpgp
```

Import the root package for the high-level API. Import `mime` and `mail` separately when needed:

```text
import {
  "justinwongcn/moonpgp",
  "justinwongcn/moonpgp/mime",
  "justinwongcn/moonpgp/mail",
}
```

The root package exposes the `@api` functions and their option types as `@moonpgp.*`. The `mime` and `mail` packages provide PGP/MIME parsing and RFC 5322 message composition.

To try the command-line demo from a clone:

```bash
git clone https://github.com/justinwongcn/moonpgp
cd moonpgp
moon run cmd/main -- help
```

## Features

- **Keys:** import, export, generate, lock, and unlock OpenPGP keys. Supports RSA, Ed25519 (EdDSA legacy), and Curve25519/X25519 workflows, with v4 keys as the default generation format and v6 support available through the relevant APIs. Key lifecycle helpers check capabilities, expiration, and revocation.
- **Messages:** public-key and passphrase encryption; detached, inline, and cleartext signatures; session-key operations; optional ZIP/ZLIB compression. AES is used for generated messages; CAST5 and 3DES are supported for decryption only.
- **Modern formats:** v6 keys and messages, including v6 PKESK/SKESK and v2 SEIPD with OCB, EAX, or GCM AEAD. Standard v4 recipient and passphrase workflows use v1 SEIPD by default.
- **Passphrase protection:** iterated-and-salted S2K and Argon2 S2K, including supported AEAD-protected secret keys.
- **Email:** `mime` parses and verifies PGP/MIME messages; `mail` builds RFC 5322 messages, including signed and encrypted PGP/MIME. SMTP/IMAP clients are examples under `example/`, not part of the library API, and support native only.

## Interoperability and checks

The test suite includes selected interoperability workflows with GnuPG, OpenSSL, and go-crypto, along with RFC test vectors. See [`scripts/interop_check.sh`](./scripts/interop_check.sh) for the GnuPG interoperability checks.

Local checks:

```bash
moon check --target all --deny-warn
moon build --target all
moon test --target native
moon fmt --check
```

CI builds and tests the native, wasm, and js targets. Native is the preferred target. Operations that generate keys or random values require a platform entropy source; availability depends on the runtime.

## Security and limitations

- Import validates the supported key signatures, including User ID certifications, subkey bindings, and v6 direct-key signatures. This is not identity or third-party trust validation; applications must establish trust in a key separately.
- Ed25519 and X25519 field arithmetic uses `@bigint` and is not constant-time. Garbage-collected runtimes also cannot guarantee private-key memory wiping.
- Decryption of untrusted Argon2-protected data is subject to a default 256 MiB memory limit. Requests above the limit are rejected before allocation; callers can choose a different limit where the API allows it.
- v2 SEIPD messages are not padded by the encryption APIs and therefore reveal approximate plaintext length.
- On targets without a platform clock, expiration checks are disabled and revocation dates cannot be evaluated; revocation signatures are still cryptographically checked. The example SMTP/IMAP transports are native-only.

See [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md) for dependency and attribution details.

## License

Apache-2.0. See [LICENSE](./LICENSE), [NOTICE](./NOTICE), and [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).
