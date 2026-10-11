#!/usr/bin/env bash
# One-shot acceptance gate: unit tests + interop + end-to-end mail flow.
# Run from the openpgp/ project root: bash scripts/acceptance.sh
#
# Step 4 also runs the RFC 9580 Appendix A.5/A.12 Argon2 end-to-end vectors,
# which are `#skip` in the default suite because each derivation allocates
# 2 GiB. They are the only RFC-vector coverage of the Argon2 S2K path, so
# they belong in the release gate rather than in the default `moon test`.
# The public decrypt entry points default to a 256 MiB Argon2 policy; these
# tests pass `argon2_max_memory_kib=ARGON2_MAX_MEMORY_KIB` (2 GiB)
# explicitly, which is exactly the documented way to open such a message.
set -e
cd "$(dirname "$0")/.."

echo "== 1/5 moon check (0 warnings expected) =="
moon check 2>&1 | tee /tmp/acceptance_check.txt
! grep -q "Warning" /tmp/acceptance_check.txt

echo "== 2/5 moon test (native) =="
moon test

echo "== 3/5 moon test (wasm) =="
moon test --target wasm

echo "== 4/5 slow RFC 9580 A.5/A.12 Argon2 vectors (2 GiB each) =="
moon test api --target native --include-skipped --filter "slow:*"

echo "== 5/5 interop + e2e =="
bash scripts/interop_check.sh
bash scripts/interop_aead_gpg.sh
bash example/mailer/e2e.sh
bash example/mailer/e2e_tls.sh

echo "ACCEPTANCE PASS"
