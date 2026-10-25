#!/usr/bin/env bash
# Regenerates the GnuPG dual-subkey interop vectors for the multi-subkey
# key model (N2):
#   interop_gpg_dualsub_key.asc     (secret key: Ed25519 primary (cert-only),
#                                    cv25519 encryption subkey, Ed25519
#                                    signing subkey — the Proton-style shape)
#   interop_gpg_dualsub_pub.asc     (its public half)
#   interop_gpg_dualsub_sig.asc     (detached signature made BY THE SIGNING
#                                    SUBKEY: the primary cannot sign, so gpg
#                                    has no other choice)
#   interop_gpg_dualsub_sig.txt     (the exact signed bytes)
#   interop_gpg_dualsub_message.asc (message gpg encrypted to the encryption
#                                    subkey)
# Requires: gpg 2.4.x on PATH. Run from the repo root.
set -euo pipefail

export GNUPGHOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT

# Primary is CERT-ONLY on purpose: every signature gpg makes below must then
# come from the signing subkey, which is exactly the path the fixtures exist
# to exercise.
gpg --batch --passphrase '' --quick-generate-key \
  "Dual Sub <dualsub@gpg.test>" ed25519 cert 0
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')
gpg --batch --passphrase '' --quick-add-key "$FPR" cv25519 encr 0
gpg --batch --passphrase '' --quick-add-key "$FPR" ed25519 sign 0

# Two subkeys on the certificate, in a known order (encr first, sign last).
gpg --list-keys --with-colons | grep -c '^sub' | grep -q '^2$'

gpg --batch --armor --export-secret-keys > testdata/interop_gpg_dualsub_key.asc
gpg --batch --armor --export > testdata/interop_gpg_dualsub_pub.asc

printf 'dual subkey interop payload\nline two\n' > testdata/interop_gpg_dualsub_sig.txt

# The signing subkey issues the detached signature (cert-only primary).
gpg --batch --pinentry-mode loopback --passphrase '' \
  --detach-sign --armor --output testdata/interop_gpg_dualsub_sig.asc \
  testdata/interop_gpg_dualsub_sig.txt
gpg --verify testdata/interop_gpg_dualsub_sig.asc testdata/interop_gpg_dualsub_sig.txt \
  2>&1 | grep "Good signature" >/dev/null

# Encrypted to the cv25519 encryption subkey.
gpg --batch --pinentry-mode loopback --passphrase '' --trust-model always \
  --encrypt --armor --recipient "dualsub@gpg.test" \
  --output testdata/interop_gpg_dualsub_message.asc \
  testdata/interop_gpg_dualsub_sig.txt

# Show the final shape for the commit message / review.
gpg --list-keys --with-colons | awk -F: '
  /^pub/ { print "primary " $4 " " $12 }
  /^sub/ { print "subkey  " $4 " " $12 }'
