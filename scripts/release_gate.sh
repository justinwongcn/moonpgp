#!/usr/bin/env bash
# Local mirror of the CI pipeline and the release gate: the same checks the
# Release workflow runs before it will tag and publish.
#
# Usage: bash scripts/release_gate.sh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

echo "== moon fmt --check"
moon fmt --check

echo "== moon check --target all --deny-warn"
moon check --target all --deny-warn

for target in native wasm js; do
  echo "== moon build --target $target"
  moon build --target "$target"
  echo "== moon test --target $target"
  moon test --target "$target"
done

echo "== smoke"
bash scripts/ci_smoke.sh

echo "gate passed — safe to tag and moon publish"
