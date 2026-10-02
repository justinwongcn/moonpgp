#!/usr/bin/env bash
#
# GnuPG interop check for justinwongcn/openpgp (moonpgp).
#
# Builds the release CLI, generates a fresh Ed25519(+cv25519) key with the
# moonpgp CLI, imports it into a throwaway GNUPGHOME, and cross-verifies six
# directions against the local gpg:
#
#   1. moonpgp sign          -> gpg --verify
#   2. gpg detach-sign       -> moonpgp verify
#   3. moonpgp encrypt (pub) -> gpg --decrypt
#   4. gpg encrypt           -> moonpgp decpriv
#   5. moonpgp encpass       -> gpg --decrypt (passphrase)
#   6. gpg --symmetric       -> moonpgp decpass
#
# Exit 0 when all six directions pass; nonzero otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENPGP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$OPENPGP_DIR/_build/native/release/build/cmd/main/main.exe"
USERID="Interop Check <interop@test.local>"
PASSPHRASE="interop-pass-1234"

WORK="$(mktemp -d /tmp/moonpgp_interop.XXXXXX)"
GNUPGHOME="$WORK/gnupg"
export GNUPGHOME
trap 'rm -rf "$WORK"' EXIT

FAILED=0
step() { printf '\n=== %s ===\n' "$1"; }
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; FAILED=1; }

step "0. build release CLI + fresh GNUPGHOME"
( cd "$OPENPGP_DIR" && moon build --release >/dev/null ) || { fail "moon build --release"; exit 1; }
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
gpg --version | head -1

step "1. generate Ed25519+cv25519 key with moonpgp, import into gpg"
"$BIN" edkeygen "$USERID" "$WORK/sec.asc" "$WORK/pub.asc" || { fail "edkeygen"; exit 1; }
if gpg --batch --import "$WORK/sec.asc" >/dev/null 2>&1; then
  pass "secret key imported by gpg"
else
  fail "gpg --import"
fi
if gpg --batch --list-keys 2>/dev/null | grep -q "ed25519"; then
  pass "gpg recognizes ed25519 primary key"
else
  fail "gpg key listing shows no ed25519"
fi

printf 'interop check message for moonpgp vs gpg\n' > "$WORK/msg.txt"

step "2. moonpgp sign -> gpg verify"
if "$BIN" sign "$WORK/sec.asc" "$WORK/msg.txt" "$WORK/our.sig" >/dev/null 2>&1; then
  if gpg --batch --verify "$WORK/our.sig" "$WORK/msg.txt" 2>&1 | grep -q "Good signature"; then
    pass "gpg verifies moonpgp signature (Good signature)"
  else
    fail "gpg --verify of moonpgp signature"
  fi
else
  fail "moonpgp sign"
fi

step "3. gpg sign -> moonpgp verify"
if gpg --batch --yes --pinentry-mode loopback --armor \
    --local-user "$USERID" --output "$WORK/gpg.sig" --detach-sign "$WORK/msg.txt" 2>/dev/null; then
  if "$BIN" verify "$WORK/pub.asc" "$WORK/msg.txt" "$WORK/gpg.sig" | grep -q "Good signature"; then
    pass "moonpgp verifies gpg signature (Good signature)"
  else
    fail "moonpgp verify of gpg signature"
  fi
else
  fail "gpg --detach-sign"
fi

step "4. moonpgp encrypt (public key) -> gpg decrypt"
if "$BIN" encpub "$WORK/pub.asc" "$WORK/msg.txt" "$WORK/our.enc.asc" >/dev/null 2>&1; then
  if gpg --batch --yes --pinentry-mode loopback \
      --output "$WORK/our.dec.txt" --decrypt "$WORK/our.enc.asc" >/dev/null 2>&1; then
    if cmp -s "$WORK/msg.txt" "$WORK/our.dec.txt"; then
      pass "gpg decrypts moonpgp ciphertext byte-identically"
    else
      fail "gpg decrypt output differs"
    fi
  else
    fail "gpg --decrypt of moonpgp ciphertext"
  fi
else
  fail "moonpgp encpub"
fi

step "5. gpg encrypt -> moonpgp decrypt"
if gpg --batch --yes --armor --trust-model always \
    --recipient "$USERID" --output "$WORK/gpg.enc.asc" --encrypt "$WORK/msg.txt" 2>/dev/null; then
  if "$BIN" decpriv "$WORK/sec.asc" "$WORK/gpg.enc.asc" "$WORK/gpg.dec.txt" >/dev/null 2>&1; then
    if cmp -s "$WORK/msg.txt" "$WORK/gpg.dec.txt"; then
      pass "moonpgp decrypts gpg ciphertext byte-identically"
    else
      fail "moonpgp decpriv output differs"
    fi
  else
    fail "moonpgp decpriv"
  fi
else
  fail "gpg --encrypt"
fi

step "6. moonpgp encpass -> gpg decrypt with passphrase"
if "$BIN" encpass "$PASSPHRASE" "$WORK/msg.txt" "$WORK/pw.enc.asc" >/dev/null 2>&1; then
  if gpg --batch --yes --pinentry-mode loopback --passphrase "$PASSPHRASE" \
      --output "$WORK/pw.dec.txt" --decrypt "$WORK/pw.enc.asc" >/dev/null 2>&1; then
    if cmp -s "$WORK/msg.txt" "$WORK/pw.dec.txt"; then
      pass "gpg decrypts moonpgp passphrase ciphertext byte-identically"
    else
      fail "gpg passphrase decrypt output differs"
    fi
  else
    fail "gpg --decrypt of moonpgp passphrase ciphertext"
  fi
else
  fail "moonpgp encpass"
fi

step "7. gpg --symmetric -> moonpgp decpass"
if gpg --batch --yes --pinentry-mode loopback --passphrase "$PASSPHRASE" \
    --symmetric --armor --output "$WORK/gpg.sym.asc" "$WORK/msg.txt" 2>/dev/null; then
  if "$BIN" decpass "$PASSPHRASE" "$WORK/gpg.sym.asc" "$WORK/gpg.sym.txt" >/dev/null 2>&1; then
    if cmp -s "$WORK/msg.txt" "$WORK/gpg.sym.txt"; then
      pass "moonpgp decrypts gpg symmetric ciphertext byte-identically"
    else
      fail "moonpgp decpass output differs"
    fi
  else
    fail "moonpgp decpass"
  fi
else
  fail "gpg --symmetric"
fi

printf '\n'
if [ "$FAILED" -eq 0 ]; then
  echo "ALL INTEROP DIRECTIONS PASSED"
  exit 0
else
  echo "SOME DIRECTIONS FAILED (see FAIL lines above)"
  exit 1
fi
