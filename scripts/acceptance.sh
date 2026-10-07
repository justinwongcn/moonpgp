#!/usr/bin/env bash
# One-shot acceptance gate: unit tests + interop + end-to-end mail flow.
# Run from the openpgp/ project root: bash scripts/acceptance.sh
set -e
cd "$(dirname "$0")/.."

echo "== 1/3 moon check (0 warnings expected) =="
moon check 2>&1 | tee /tmp/acceptance_check.txt
! grep -q "Warning" /tmp/acceptance_check.txt

echo "== 2/3 moon test =="
moon test

echo "== 3/3 interop + e2e =="
bash scripts/interop_check.sh
bash scripts/interop_aead_gpg.sh
bash example/mailer/e2e.sh
bash example/mailer/e2e_tls.sh

echo "ACCEPTANCE PASS"
