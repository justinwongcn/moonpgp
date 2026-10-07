#!/usr/bin/env bash
# End-to-end acceptance for the TLS transports (plan tls-transport
# M2/M3): full PGP/MIME compose + send against a local TLS sink
# (tls_sink.py, python3 stdlib, self-signed cert).
#   case 1: implicit TLS + trust pem:server.crt  -> stored + gpg verified
#   case 2: STARTTLS  + trust pem:server.crt     -> stored + gpg verified
#   case 3: implicit TLS + trust none            -> stored + LOUD warning
#   case 4: implicit TLS + WRONG pem pin         -> aborts, sink gets nothing
# Exit 0 only when every gate passes.
set -euo pipefail
cd "$(dirname "$0")/../.."            # openpgp/ project root

TMP=$(mktemp -d)
cleanup() { [[ -n "${SINK_PID:-}" ]] && kill "$SINK_PID" 2>/dev/null || true; }
trap cleanup EXIT

fail() { echo "E2E-TLS FAIL: $*" >&2; exit 1; }

# ---------- fixtures ----------
mkdir -p "$TMP/sink" "$TMP/ca"
printf 'End-to-end TLS body from moonpgp.\r\nSecond line with .dot prefix test.\r\n' > "$TMP/body.txt"
printf 'attachment line one\nattachment line two\n' > "$TMP/note.txt"
KEY=testdata/interop_our_key.asc      # RSA-1024, no passphrase

# Self-signed server cert; OpenSSL 3 hostname verification requires a
# subjectAltName, so the sink cert must carry IP:127.0.0.1.
openssl req -x509 -newkey rsa:2048 \
  -keyout "$TMP/ca/key.pem" -out "$TMP/ca/cert.pem" -days 2 -nodes \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null \
  || fail "openssl req failed (is openssl installed?)"
CERT="$TMP/ca/cert.pem"

# ---------- gpg two-step verification (same as e2e.sh gates 2-3) ----------
verify_stored() {
  local eml="$1"
  export GNUPGHOME="$TMP/gnupg"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
  gpg --batch --import "$KEY" >/dev/null 2>&1
  # Bounded retry for the intermittent gpg-agent flake (~1% wrong RSA
  # plaintext with the legacy interop fixture; HANDOFF §16 has the
  # evidence) — with a visible NOTE so real regressions stay loud.
  gpg_decrypt_stored() {
    gpg --batch --pinentry-mode loopback --decrypt "$eml" \
      > "$TMP/decrypted.eml" 2>"$TMP/decrypt.log"
  }
  gpg_decrypt_stored || {
    echo "NOTE: gpg --decrypt failed once (known gpg-agent flake), retrying"
    gpg_decrypt_stored
  } || fail "gpg --decrypt failed"
  grep -q "encrypted with" "$TMP/decrypt.log" || fail "message was not actually encrypted"
  python3 - "$TMP/decrypted.eml" "$TMP" <<'PY'
import sys, re
raw = open(sys.argv[1], "rb").read()
m = re.search(rb'Content-Type: multipart/signed;[^\r\n]*boundary="([^"]+)"', raw)
assert m, "decrypted payload is not multipart/signed"
b = m.group(1)
parts = raw.split(b"--" + b + b"\r\n")[1:]
assert len(parts) >= 2, "expected two multipart/signed parts"
part1 = parts[0]
sig = parts[1].split(b"\r\n\r\n", 1)[1]
if sig.endswith(b"\r\n"):
    sig = sig[:-2]
open(sys.argv[2] + "/part1.bin", "wb").write(part1)
open(sys.argv[2] + "/sig.asc", "wb").write(sig)
PY
  gpg --batch --pinentry-mode loopback --verify "$TMP/sig.asc" "$TMP/part1.bin" \
    2>"$TMP/verify.log" || fail "gpg --verify failed"
  grep -q "Good signature" "$TMP/verify.log" || fail "no Good signature"
  cmp <(python3 - "$TMP/part1.bin" <<'PY'
import sys, re
raw = open(sys.argv[1], "rb").read()
b = re.search(rb'boundary="([^"]+)"', raw).group(1)
seg = raw.split(b"--" + b + b"\r\n")[1]
body = seg.split(b"\r\n\r\n", 1)[1]
sys.stdout.buffer.write(body)
PY
) "$TMP/body.txt" || fail "text payload differs from the composed body"
}

# ---------- one TLS send case ----------
send_case() {
  local mode="$1" trust="$2" want_warning="$3" tag="$4"
  local port=$((21000 + RANDOM % 20000))
  rm -rf "$TMP/sink"; mkdir -p "$TMP/sink"
  python3 example/mailer/tls_sink.py "$port" "$TMP/sink" "$CERT" "$TMP/ca/key.pem" "$mode" \
    > "$TMP/sink.log" 2>&1 &
  SINK_PID=$!
  for _ in $(seq 1 100); do
    grep -q "SINK READY" "$TMP/sink.log" 2>/dev/null && break
    sleep 0.1
  done
  grep -q "SINK READY" "$TMP/sink.log" || fail "[$tag] sink did not come up"

  moon run example/mailer --target native -- \
    --from "MoonBit Sender <sender@mailpgp.example>" \
    --to "MoonBit Recipient <rcpt@mailpgp.example>" \
    --subject "e2e tls $tag" \
    --body-file "$TMP/body.txt" \
    --attach note.txt:"$TMP/note.txt" \
    --sender-key "$KEY" \
    --recipient-cert "$KEY" \
    --domain mailpgp.example \
    --mode smtp --smtp-host 127.0.0.1 --smtp-port "$port" \
    --smtp-tls "$mode" --smtp-trust "$trust" \
    > "$TMP/run.log" 2>&1 \
    || { tail -5 "$TMP/run.log" >&2; fail "[$tag] moon run exited non-zero"; }
  kill "$SINK_PID" 2>/dev/null || true
  SINK_PID=""

  test -f "$TMP/sink/msg-0.eml" || fail "[$tag] sink never stored the message"
  if [[ "$want_warning" == "yes" ]]; then
    grep -q "verification is DISABLED" "$TMP/run.log" \
      || fail "[$tag] expected the loud --smtp-trust none warning on stderr"
    echo "--- [$tag] PASS: stored over $mode; warning printed as required"
  else
    verify_stored "$TMP/sink/msg-0.eml"
    echo "--- [$tag] PASS: composed, signed, encrypted, sent over $mode (trust $trust); gpg verifies"
  fi
}

# ---------- the three positive gates ----------
send_case implicit "pem:$CERT" no  "implicit+pem"
send_case starttls "pem:$CERT" no  "starttls+pem"
send_case implicit none       yes  "implicit+none"

# ---------- negative gate: a wrong pin must abort before any SMTP data ----------
# A second self-signed cert: valid PEM, but not the certificate the sink
# presents, so the post-handshake pin check must fail and the process
# must exit non-zero with nothing stored (review 2026-10-06 P3).
openssl req -x509 -newkey rsa:2048 \
  -keyout "$TMP/ca/other-key.pem" -out "$TMP/ca/other-cert.pem" -days 2 -nodes \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null \
  || fail "openssl req (second cert) failed"
PORT=$((21000 + RANDOM % 20000))
rm -rf "$TMP/sink"; mkdir -p "$TMP/sink"
python3 example/mailer/tls_sink.py "$PORT" "$TMP/sink" "$CERT" "$TMP/ca/key.pem" implicit \
  > "$TMP/sink.log" 2>&1 &
SINK_PID=$!
for _ in $(seq 1 100); do
  grep -q "SINK READY" "$TMP/sink.log" 2>/dev/null && break
  sleep 0.1
done
grep -q "SINK READY" "$TMP/sink.log" || fail "[implicit+badpin] sink did not come up"
if moon run example/mailer --target native -- \
  --from "MoonBit Sender <sender@mailpgp.example>" \
  --to "MoonBit Recipient <rcpt@mailpgp.example>" \
  --subject "e2e tls implicit+badpin" \
  --body-file "$TMP/body.txt" \
  --sender-key "$KEY" \
  --recipient-cert "$KEY" \
  --domain mailpgp.example \
  --mode smtp --smtp-host 127.0.0.1 --smtp-port "$PORT" \
  --smtp-tls implicit --smtp-trust "pem:$TMP/ca/other-cert.pem" \
  > "$TMP/run.log" 2>&1; then
  kill "$SINK_PID" 2>/dev/null || true
  SINK_PID=""
  fail "[implicit+badpin] expected a non-zero exit on pin mismatch"
fi
kill "$SINK_PID" 2>/dev/null || true
SINK_PID=""
grep -q "does not match the pinned" "$TMP/run.log" \
  || fail "[implicit+badpin] expected the pin-mismatch error on stderr"
test ! -f "$TMP/sink/msg-0.eml" \
  || fail "[implicit+badpin] sink stored a message despite the pin mismatch"
echo "--- [implicit+badpin] PASS: wrong pin aborts the submission, sink received nothing"

echo "E2E-TLS PASS: implicit and STARTTLS submissions verified; insecure trust warned; wrong pin refused."
rm -rf "$TMP"
