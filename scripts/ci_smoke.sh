#!/usr/bin/env bash
# README quick-start smoke test — the minimal runnable example, executed by CI.
#
# Runs the CLI demo from a temporary directory and asserts the roundtrip:
# keygen -> public-key encrypt -> private-key decrypt returns the input
# byte-for-byte. Also exercises every documented subcommand once.
#
# Usage: bash scripts/ci_smoke.sh      (from the repository root)
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run() { moon run cmd/main --target native -- "$@"; }

echo "== help =="
run help >/dev/null

echo "== keygen (RSA 2048, default minimum bits) =="
run keygen "Smoke <smoke@example.com>" "$work/sec.asc" "$work/pub.asc" 2048

echo "== edkeygen / v6keygen =="
run edkeygen "Smoke <smoke@example.com>" "$work/ed.asc" "$work/ed-pub.asc"
run v6keygen "Smoke <smoke@example.com>" "$work/v6.asc" "$work/v6-pub.asc"

printf 'hello moonpgp\n' > "$work/plain.txt"

echo "== passphrase encrypt/decrypt =="
run encpass "smoke-passphrase" "$work/plain.txt" "$work/pw.asc"
run decpass "smoke-passphrase" "$work/pw.asc" "$work/pw.out"
cmp "$work/plain.txt" "$work/pw.out"

echo "== public-key encrypt / private-key decrypt =="
run encpub "$work/pub.asc" "$work/plain.txt" "$work/pub.msg.asc"
run decpriv "$work/sec.asc" "$work/pub.msg.asc" "$work/pub.out"
cmp "$work/plain.txt" "$work/pub.out"

echo "== detached sign / verify =="
run sign "$work/sec.asc" "$work/plain.txt" "$work/plain.sig.asc"
run verify "$work/pub.asc" "$work/plain.txt" "$work/plain.sig.asc"

echo "== lock / decrypt with passphrase / unlock =="
run lock "$work/sec.asc" "smoke-passphrase"
run encpub "$work/pub.asc" "$work/plain.txt" "$work/locked.msg.asc"
run decpriv "$work/sec.asc" "smoke-passphrase" "$work/locked.msg.asc" "$work/locked.out"
cmp "$work/plain.txt" "$work/locked.out"
run unlock "$work/sec.asc" "smoke-passphrase"
run decpriv "$work/sec.asc" "$work/locked.msg.asc" "$work/unlocked.out"
cmp "$work/plain.txt" "$work/unlocked.out"

echo "== tag-20 AEAD (v5 SKESK) passphrase roundtrip =="
run encpass "smoke-passphrase" "$work/plain.txt" "$work/aead.asc" aead
run decpass "smoke-passphrase" "$work/aead.asc" "$work/aead.out"
cmp "$work/plain.txt" "$work/aead.out"

echo "CI SMOKE PASS"
