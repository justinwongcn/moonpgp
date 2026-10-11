#!/usr/bin/env bash
# GnuPG AEAD (tag 20 / OCB) interop gate: the draft-ietf-openpgp-rfc4880bis
# AEAD shapes GnuPG 2.4 produces under --force-aead.
#   direction A: moonpgp --aead message  -> gpg --decrypt  (byte-identical)
#   direction B: gpg --force-aead        -> moonpgp decpass (byte-identical)
# The RFC's own A.4 sample is covered by api/password_test.mbt; this
# gate exercises the live gpg implementation on both sides.
# Run from the openpgp/ project root: bash scripts/interop_aead_gpg.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PASS="aead-interop-password-2026"
TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
export GNUPGHOME="$TMP/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

fail() { echo "AEAD-INTEROP FAIL: $*" >&2; exit 1; }

gpg --version >/dev/null 2>&1 || fail "gpg not installed"
if ! gpg --dump-options 2>/dev/null | grep -q -- "--force-aead"; then
  fail "this gpg has no --force-aead (GnuPG >= 2.4 required)"
fi

printf 'moonpgp aead interop payload\nsecond line\n' > "$TMP/plain.txt"

echo "== A. moonpgp (v5 SKESK + tag 20) -> gpg --decrypt =="
moon run cmd/main --target native -- encpass "$PASS" "$TMP/plain.txt" "$TMP/ours.asc" aead \
  > /dev/null || fail "moonpgp encpass aead failed"
gpg --batch --pinentry-mode loopback --passphrase "$PASS" \
  --decrypt "$TMP/ours.asc" > "$TMP/from-gpg.out" 2>"$TMP/a.log" \
  || { tail -3 "$TMP/a.log" >&2; fail "gpg refused the moonpgp AEAD message"; }
cmp "$TMP/from-gpg.out" "$TMP/plain.txt" \
  || fail "gpg output differs from the original plaintext"
grep -q "OCB" "$TMP/a.log" || fail "gpg did not report an OCB session"
echo "PASS: gpg decrypted the moonpgp AEAD message byte-identically"

echo "== B. gpg --force-aead -> moonpgp decpass =="
gpg --batch --pinentry-mode loopback --passphrase "$PASS" \
  --symmetric --force-aead --aead-algo ocb --s2k-digest-algo SHA256 --armor \
  -o "$TMP/from-gpg.asc" < "$TMP/plain.txt" 2>"$TMP/b.log" \
  || { tail -3 "$TMP/b.log" >&2; fail "gpg --force-aead encryption failed"; }
moon run cmd/main --target native -- decpass "$PASS" "$TMP/from-gpg.asc" "$TMP/from-moon.out" \
  > /dev/null || fail "moonpgp decpass failed on the gpg AEAD message"
cmp "$TMP/from-moon.out" "$TMP/plain.txt" \
  || fail "moonpgp output differs from the gpg plaintext"
echo "PASS: moonpgp decrypted the gpg --force-aead message byte-identically"

echo "AEAD-INTEROP PASS: tag-20 OCB shapes round-trip with GnuPG in both directions."
