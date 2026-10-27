# Contributing

Thanks for looking into moonpgp. Issues and pull requests are welcome;
English or Chinese, whichever you prefer.

## Setup

You need the MoonBit toolchain (`moon`), and GnuPG for the interop scripts.

```bash
moon update
moon check --target all --deny-warn
moon test --target all
```

Run `moon fmt` before committing — CI rejects unformatted code. The whole
pipeline CI runs (format, strict check, build and test on native/wasm/js,
and an end-to-end smoke test) can be replayed locally with:

```bash
bash scripts/release_gate.sh
```

## Pull requests

Keep one change per PR. Code changes need tests; parser and packet paths
also need a malformed-input test. If you touch the wire format, key
handling, or anything the library emits armored, run the GnuPG interop
scripts and note the result in the PR:

```bash
bash scripts/interop_check.sh
```

## Reporting security problems

Please do not open a public issue for a security problem. See
[SECURITY.md](SECURITY.md) for the private reporting channel.

## Releases (maintainers)

A release is never cut from a red tree. The order:

1. Finalize the CHANGELOG under `[Unreleased]`, run `moon publish`.
2. Rename the section to `[X.Y.Z]` with the date, commit.
3. Dispatch the **Release** workflow: it runs the full pipeline and only
   then tags `vX.Y.Z` and opens the GitHub Release, taking the notes from
   the CHANGELOG section of that version.

`scripts/release_gate.sh` is the same gate for a terminal, if you would
rather check locally before dispatching.
