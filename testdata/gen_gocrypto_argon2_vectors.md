# go-crypto interop fixtures

Six fixtures in this directory were produced by
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto), i.e. by a
different OpenPGP implementation than this repository's MoonBit library. They
are the *other side* of the differential tests in
`src/interop/argon2_cross_test.mbt` and `src/interop/v6_aead_pref_test.mbt`:
go-crypto writes, we read.

This file is the reproduction recipe. It replaces an earlier version that
embedded a Go listing that did not compile (unused imports, no `main`) plus a
pasted stdout transcript.

## Pinned version

**`github.com/ProtonMail/go-crypto v1.5.2`** — pinned in
[`gocrypto/go.mod`](gocrypto/go.mod) and recorded with hashes in
`gocrypto/go.sum`. The generator was run with **Go 1.27.1 (darwin/arm64)**.

`v1.4.1` is the release gopenpgp v3 pins and the one the old text of this
file named. The generator was also compiled and run against `v1.4.1` while
checking this task: with the only source change needed
(`openpgp.MessageType` → the literal `"PGP MESSAGE"`, which that release does
not export), it produced the *same structure* for all six fixtures. The two
releases are therefore structurally indistinguishable on these inputs; `v1.5.2`
is pinned because it is the release the v6 AEAD test already cites and the one
present in this machine's module cache. The comments in
`src/interop/argon2_cross_test.mbt` were updated to match (they name the
generator rather than a single version).

## Generate

The generator is a self-contained Go module in `gocrypto/`. It never writes
into `testdata/` unless you explicitly point it there, and it refuses to
overwrite an existing file without `-force`.

```sh
cd testdata/gocrypto

# Default: a fresh temporary directory; the path is printed.
go run .

# A caller-given directory:
go run . -out /tmp/gocrypto-fixtures

# Overwrite files that already exist:
go run . -out /tmp/gocrypto-fixtures -force

# Optional: pin the key creation timestamp (otherwise time.Now is used).
go run . -out /tmp/gocrypto-fixtures -time 2026-10-07T18:30:59Z
```

Actual run used for the comparison below (Go 1.27.1, go-crypto v1.5.2); the
hashes are from that one run and change on every run, the byte counts do not:

```console
$ cd testdata/gocrypto
$ GEN=$(mktemp -d /tmp/gocrypto-gen2-XXXX)
$ go run . -out "$GEN" -time 2026-10-07T18:30:59Z
go-crypto v1.5.2 fixtures -> /tmp/gocrypto-gen2-bqZy

interop_gocrypto_v4_argon2_key.asc           3814 bytes  sha256=ec5db4c246ce801c645d535d79cd5a992445f7204a15beb60fbf519ba03217dd
interop_gocrypto_v6_argon2_key.asc           4196 bytes  sha256=d799dcecbc5eab8428a7142b4cd56fa0086247bcabc059af10252b6461a12d6f
interop_gocrypto_v6_aead_key.asc              942 bytes  sha256=61083efad6df534f194f4aeb4332c7f68a441236e887faea9176ccb48f9bd988
interop_gocrypto_argon2_msg.asc               235 bytes  sha256=c3b1f1362f93a13fc8f89103993bcebbb7ea1e3cbe24599af740b312d406a461
interop_gocrypto_v6_aead_msg.asc              353 bytes  sha256=c7b5ba78b494a12260c7372d25125adb3fbae004094f9e2ab0466de2a51e59e9
interop_gocrypto_v6_aead_skesk_msg.asc        296 bytes  sha256=cbc5bb2b73a6b5685e9cdfd1f3ed7ac2c76231d0664c39cebc5cbc60963dea68

done; plaintexts and passphrases are listed in README.md
```

The six byte counts are **identical** to the committed fixtures (3814, 4196,
942, 235, 353, 296). Byte-for-byte identity is neither expected nor achieved:
key material, S2K salts, signature salts and AEAD nonces are random.

See [`gocrypto/README.md`](gocrypto/README.md) for the module layout and the
verification helpers.

## What each fixture really is

All facts below were read out of the committed bytes with
`gocrypto/inspect_fixtures.py`; the packet versions, algorithms, protection
state and plaintexts were independently confirmed with `gocrypto/verify`
(go-crypto's own reader). The `created` values are the fixtures' own fields.

| Fixture | Packets | Key algorithm | Protection | S2K | Passphrase | Plaintext |
| --- | --- | --- | --- | --- | --- | --- |
| `interop_gocrypto_v4_argon2_key.asc` | v4 SecretKey, UserID, v4 positive-cert sig, v4 SecretSubkey, v4 subkey-binding sig | RSA-2048 primary + RSA-2048 subkey | S2K usage **253** (AEAD), AES-128, OCB | type 4 **Argon2id**, t=1, p=1, m=2^5 (32 KiB) | `go-crypto-argon2` | — (key) |
| `interop_gocrypto_v6_argon2_key.asc` | v6 SecretKey, v6 direct-key sig, UserID, v6 positive-cert sig, v6 SecretSubkey, v6 subkey-binding sig | **RSA-2048** primary + **RSA-2048** subkey (not Ed25519) | S2K usage **253** (AEAD), AES-128, OCB | type 4 **Argon2id**, t=1, p=1, m=2^5 (32 KiB) | `go-crypto-argon2` | — (key) |
| `interop_gocrypto_argon2_msg.asc` | v4 SKESK, v1 SEIPD (MDC) | — (symmetric) | SKESK cipher AES-128, 17-byte encrypted session key | type 4 **Argon2id**, t=1, p=1, m=2^5 (32 KiB) | `go-crypto-argon2` | `written by go-crypto with Argon2 S2K\n` |
| `interop_gocrypto_v6_aead_key.asc` | v6 SecretKey, v6 direct-key sig, UserID, v6 positive-cert sig, v6 SecretSubkey, v6 subkey-binding sig | **Ed25519** primary + **X25519** subkey | S2K usage **0** — UNPROTECTED despite the "aead" in the name | none | none | — (key) |
| `interop_gocrypto_v6_aead_msg.asc` | v6 PKESK (key version 6, X25519), v2 SEIPD | recipient = the v6 X25519 subkey above | SEIPD v2 AES-128/OCB, chunk octet **12** | n/a (public-key encrypted) | none | `written by go-crypto v6 PKESK + SEIPD v2\n` |
| `interop_gocrypto_v6_aead_skesk_msg.asc` | v6 SKESK, v2 SEIPD | — (symmetric) | SKESK v6 AES-128/OCB, 32-byte encrypted session key | type 3 **iterated-salted**, SHA-256, count octet 224 (16,777,216) — **not Argon2** | `go-crypto-v6` | `written by go-crypto v6 SKESK\n` |

The three plaintext strings are asserted verbatim by
`src/interop/argon2_cross_test.mbt`; a regenerated fixture must keep them.

Extra detail that is easy to get wrong:

* `interop_gocrypto_v4_argon2_key.asc` — the v4 self-signatures carry
  go-crypto's randomized-signature salt as the notation
  **`salt@notations.openpgpjs.org`** (hashed subpacket 20, 16-byte value),
  because go-crypto randomizes v4 signatures through that notation by default.
  Its hashed subpackets are: creation time (2, critical), preferred symmetric
  algorithms (11 = `[7]`), issuer key id (16), the salt notation (20),
  preferred hashes (21 = `[8]`), preferred compression (22 = `[0]`), primary
  user id (25), key flags (27, critical, `0x03`), features (30, `0x01` =
  SEIPDv1), issuer fingerprint (33).
* The **v6** keys do **not** carry that notation: go-crypto only uses it for
  `Version < 6` signatures. The v6 Argon2 key's direct-key signature has
  features `0x01` and **no** Preferred AEAD Ciphersuites subpacket, so it
  advertises SEIPDv1 only.
* `interop_gocrypto_v6_aead_key.asc` — the v6 direct-key signature advertises
  Preferred AEAD Ciphersuites (subpacket 39) as exactly `[(AES-128, OCB)]` and
  features `0x09` (SEIPDv1 | SEIPDv2). That single preference is what
  `src/interop/v6_aead_pref_test.mbt` pins.
* v6 protected secret keys add two one-octet "count of the following field"
  values (before the cipher octet and before the S2K specifier); the raw parser
  reports them as `count_before_cipher` / `count_before_s2k`.

The `created` timestamps of the committed fixtures are
2026-10-07T18:30:59Z (both Argon2 keys) and 2026-10-07T19:18:14Z (v6 AEAD key).

## Verification: committed vs regenerated

Two independent readers were used:

```sh
# raw, implementation-independent structure dump
python3 testdata/gocrypto/inspect_fixtures.py testdata/interop_gocrypto_v4_argon2_key.asc

# masked machine diff: S2K/signature salts, fingerprints and creation
# timestamps are replaced, everything structural is compared
python3 testdata/gocrypto/inspect_fixtures.py --json --canonical testdata/<f>.asc
python3 testdata/gocrypto/inspect_fixtures.py --json --canonical "$GEN/<f>.asc"

# go-crypto reads its own output back
cd testdata/gocrypto && go run ./verify -dir "$GEN"
```

Result of the masked diff (all six files):

| Fixture | Committed structure | Generated structure | Match |
| --- | --- | --- | --- |
| `interop_gocrypto_v4_argon2_key.asc` | v4 RSA-2048 + v4 RSA-2048 subkey; usage 253; AES-128/OCB; Argon2 t=1 p=1 m=2^5; notation `salt@notations.openpgpjs.org` on both self-sigs; 664 encrypted private bytes per key | identical | **yes** |
| `interop_gocrypto_v6_argon2_key.asc` | v6 RSA-2048 + v6 RSA-2048 subkey; usage 253; AES-128/OCB; Argon2 t=1 p=1 m=2^5; no notation; count octets 38/20; 664 encrypted private bytes per key | identical | **yes** |
| `interop_gocrypto_argon2_msg.asc` | v4 SKESK (AES-128, Argon2 t=1 p=1 m=2^5, 17-byte ESK) + v1 SEIPD | identical | **yes** |
| `interop_gocrypto_v6_aead_key.asc` | v6 Ed25519 + v6 X25519; usage 0 (unprotected); direct-key sig has Preferred AEAD `[(AES-128, OCB)]`, features `0x09` | identical | **yes** |
| `interop_gocrypto_v6_aead_msg.asc` | v6 PKESK (X25519, key version 6) + v2 SEIPD AES-128/OCB chunk 12 | identical | **yes** |
| `interop_gocrypto_v6_aead_skesk_msg.asc` | v6 SKESK (AES-128/OCB, iterated-salted SHA-256, count octet 224) + v2 SEIPD AES-128/OCB chunk 12 | identical | **yes** |

`go run ./verify` decrypts the regenerated messages to exactly:

```text
interop_gocrypto_v4_argon2_key.asc: unlocked with "go-crypto-argon2", still_protected=false subkeys=1
interop_gocrypto_v6_argon2_key.asc: unlocked with "go-crypto-argon2", still_protected=false subkeys=1
interop_gocrypto_v6_aead_key.asc: not protected, no passphrase needed, subkeys=1
interop_gocrypto_argon2_msg.asc: plaintext="written by go-crypto with Argon2 S2K\n" bytes=37
interop_gocrypto_v6_aead_msg.asc: plaintext="written by go-crypto v6 PKESK + SEIPD v2\n" bytes=41
interop_gocrypto_v6_aead_skesk_msg.asc: plaintext="written by go-crypto v6 SKESK\n" bytes=30
```

The committed fixtures decrypt to the same strings with the same tool.

### GnuPG cross-check

`gpg --list-packets` (GnuPG 2.4.5, libgcrypt 1.10.3) can only help on the v4
fixtures: it rejects Argon2 S2K (`unknown S2K mode 4`) and every v6 packet
(`packet(5) with unknown version 6`). On the v4 key it confirms the framing
exactly (`plen=971`, `version 4, algo 1`, `pkey[0]: [2048 bits]`, the same user
ID, and `S2K pseudo algo 253`); only the random key id and digest differ.

## Reproducibility caveat

Regeneration is **structural**, not byte-identical: RSA key material, S2K
salts, the v4 signature salt notation, and AEAD nonces/salts are random, and
so are key fingerprints and signature packet bytes. Use `-time` to pin the one
deterministic input. Two consecutive generator runs differ in bytes but are
equal under `inspect_fixtures.py --canonical`.

## Removed: the "reverse direction" transcript

The previous version of this file ended with a hand-pasted transcript headed
"Reverse direction (checked manually)". It referred to fixtures
`our_v4_argon2_key.asc`, `our_argon2_msg.asc`, `our_v6_argon2_key.asc`,
`our_v6_msg.asc`, `our_v6_skesk_msg.asc`, `our_v6_argon2_skesk_msg.asc` and
`our_v6_inline.asc`. **None of those files exists in the repository or is
generated by any test or script** (the only `our*` fixtures on disk are
`interop_our_key.asc`, `interop_our_ecdh_key.asc`,
`interop_our_ecdh_message.asc`), and the harness that allegedly produced the
transcript is not checked in. The transcript was therefore unverifiable and
has been dropped.

The direction that *is* reproducible from this repository remains
go-crypto-writes → we-read, plus the RFC 9580 Appendix A.5/A.12 fixtures in
`src/api/argon2_test.mbt`, which are self-contained.
