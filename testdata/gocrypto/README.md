# go-crypto interop fixture generator

This directory is a **separate Go module** whose only job is to regenerate the
six `testdata/interop_gocrypto_*.asc` fixtures consumed by
`src/interop/argon2_cross_test.mbt` and `src/interop/v6_aead_pref_test.mbt`.

It exists because the fixtures must come from a *different* OpenPGP
implementation than this repository's MoonBit library, and the previous
reproduction recipe (a Go snippet pasted into a Markdown file) did not compile.

* Module: `github.com/moonbit-openpgp/openpgp/testdata/gocrypto`
* Pinned library: `github.com/ProtonMail/go-crypto v1.5.2` (see `go.mod`)
* Go toolchain used while writing this: `go1.27.1 darwin/arm64`

The per-fixture description, the pinned version rationale and the structure
comparison against the committed files live in
[`../gen_gocrypto_argon2_vectors.md`](../gen_gocrypto_argon2_vectors.md).

## Layout

| Path | Purpose |
| --- | --- |
| `main.go` | the generator (writes the six fixtures) |
| `go.mod`, `go.sum` | pinned module definition |
| `verify/main.go` | reads fixtures back with go-crypto: packet dump + unlock + decrypt |
| `inspect_fixtures.py` | raw byte-level packet/S2K parser, independent of go-crypto and GnuPG |

## Generate

```sh
cd testdata/gocrypto

# Into a fresh temporary directory (the default), then print the path:
go run .

# Into a directory you choose:
go run . -out /tmp/gocrypto-fixtures

# Overwrite existing files in that directory:
go run . -out /tmp/gocrypto-fixtures -force

# Pin the key creation timestamp instead of using "now":
go run . -out /tmp/gocrypto-fixtures -time 2026-10-07T18:30:59Z
```

Safety: the generator **refuses to overwrite an existing file without
`-force`**, and without `-out` it only ever writes to a fresh temp directory.
It therefore cannot clobber the committed `testdata/*.asc` fixtures by
accident; writing into `testdata/` requires both `-out ../` and `-force`.

## Verify

```sh
cd testdata/gocrypto

# go-crypto's own view of the fixtures, plus the decrypted plaintexts:
go run ./verify -dir /tmp/gocrypto-fixtures

# Independent raw parse (all six files; no go-crypto, no GnuPG):
python3 inspect_fixtures.py /tmp/gocrypto-fixtures/*.asc
```

`inspect_fixtures.py --json --canonical FILE` prints a machine-diffable
summary in which the genuinely random fields (S2K salt, key fingerprint,
signature salt, creation timestamp) are masked; two structurally identical
files produce byte-identical output.

## Reproducibility caveat

Key material, signature salts, S2K salts and AEAD nonces are random, so
regeneration is **structurally** reproducible but **not byte-identical**. Only
`-time` is deterministic; everything else changes on every run.
