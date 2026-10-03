#!/usr/bin/env bash
# End-to-end acceptance for example/mailer (plan v2, HANDOFF §8.5):
#   1. mini-sink (python3 stdlib, no deps) on a random port
#   2. moon run example/mailer --mode smtp (real socket, real SMTP wire)
#   3. two-step gpg verification: gpg --decrypt does NOT verify the
#      MIME-level signature, so we decrypt first, split the
#      multipart/signed, then gpg --verify the parts
#   4. --roundtrip self-check through @mime.decrypt_mime
# Exit 0 only when every gate passes.
set -euo pipefail
cd "$(dirname "$0")/../.."            # openpgp/ project root

TMP=$(mktemp -d)
SINK_PORT=$((20000 + RANDOM % 20000))
# kill the sink on any exit; the temp dir is only removed on SUCCESS
# so that failures preserve the evidence (HANDOFF 8.5)
cleanup() { kill "$SINK_PID" 2>/dev/null || true; }
trap cleanup EXIT

fail() { echo "E2E FAIL: $*" >&2; exit 1; }

# ---------- fixtures ----------
mkdir -p "$TMP/sink"
printf 'End-to-end body from moonpgp.\r\nSecond line with .dot prefix test.\r\n' > "$TMP/body.txt"
printf 'attachment line one\nattachment line two\n' > "$TMP/note.txt"
KEY=testdata/interop_our_key.asc      # RSA-1024, no passphrase

# ---------- 1. mini-sink ----------
python3 - "$SINK_PORT" "$TMP/sink" > "$TMP/sink.log" 2>&1 <<'PY' &
import socket, sys, os
port, outdir = int(sys.argv[1]), sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
print("SINK READY", flush=True)
conn, _ = s.accept()
conn.sendall(b"220 mini-sink ESMTP\r\n")
in_data = False
buf = b""
n = 0
while True:
    line = b""
    while not line.endswith(b"\n"):
        ch = conn.recv(1)
        if not ch:
            sys.exit(0)
        line += ch
    if in_data:
        if line == b".\r\n":
            in_data = False
            with open(os.path.join(outdir, "msg-0.eml"), "wb") as f:
                f.write(buf)
            conn.sendall(b"250 stored\r\n")
        elif line.startswith(b".."):
            buf += line[1:]              # dot-unstuffing (receiver's job)
        else:
            buf += line
    else:
        cmd = line.decode(errors="replace").strip().upper()
        if cmd.startswith("EHLO"):
            conn.sendall(b"250-mini-sink\r\n250 OK\r\n")
        elif cmd == "DATA":
            in_data = True
            conn.sendall(b"354 end with .\r\n")
        elif cmd == "QUIT":
            conn.sendall(b"221 bye\r\n")
            break
        else:
            conn.sendall(b"250 OK\r\n")
conn.close()
PY
SINK_PID=$!
# wait for the sink to bind (its stdout goes to sink.log; a TCP probe
# would consume the sink's single accept)
for _ in $(seq 1 100); do
  grep -q "SINK READY" "$TMP/sink.log" 2>/dev/null && break
  sleep 0.1
done
grep -q "SINK READY" "$TMP/sink.log" || fail "sink did not come up"

# ---------- 2. real send over SMTP ----------
moon run example/mailer --target native -- \
  --from "MoonBit Sender <sender@mailpgp.example>" \
  --to "MoonBit Recipient <rcpt@mailpgp.example>" \
  --subject "e2e signed encrypted mail" \
  --body-file "$TMP/body.txt" \
  --attach note.txt:"$TMP/note.txt" \
  --sender-key "$KEY" \
  --recipient-cert "$KEY" \
  --domain mailpgp.example \
  --mode smtp --smtp-host 127.0.0.1 --smtp-port "$SINK_PORT" \
  || fail "moon run (smtp transport) exited non-zero"

test -f "$TMP/sink/msg-0.eml" || fail "sink never stored the message"
echo "--- gate 1 PASS: message accepted by the SMTP sink ---"

# ---------- 3. two-step gpg verification ----------
export GNUPGHOME="$TMP/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --batch --import "$KEY" >/dev/null 2>&1
gpg --batch --pinentry-mode loopback --decrypt "$TMP/sink/msg-0.eml" \
  > "$TMP/decrypted.eml" 2>"$TMP/decrypt.log" \
  || fail "gpg --decrypt failed"
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
# segs[1] IS the signed entity: its trailing CRLF (eaten by the
# delimiter) is part of the signed data per RFC 3156 §5 — keep it.
sig = parts[1].split(b"\r\n\r\n", 1)[1]
if sig.endswith(b"\r\n"):              # strip the pre-closing-boundary CRLF
    sig = sig[:-2]
open(sys.argv[2] + "/part1.bin", "wb").write(part1)
open(sys.argv[2] + "/sig.asc", "wb").write(sig)
PY
gpg --batch --pinentry-mode loopback --verify "$TMP/sig.asc" "$TMP/part1.bin" \
  2>"$TMP/verify.log" || fail "gpg --verify failed"
grep -q "Good signature" "$TMP/verify.log" || fail "no Good signature"
echo "--- gate 2 PASS: gpg verified the inner signature over the exact part bytes ---"

# ---------- 4. payload byte comparison ----------
# part1 is a multipart/mixed with a RANDOM boundary; extract its text
# payload (first part, after the blank line) and compare bytes.
python3 - "$TMP/part1.bin" "$TMP/part_body.bin" <<'PY'
import sys
raw = open(sys.argv[1], "rb").read()
import re
b = re.search(rb'boundary="([^"]+)"', raw).group(1)
seg = raw.split(b"--" + b + b"\r\n")[1]
body = seg.split(b"\r\n\r\n", 1)[1]
open(sys.argv[2], "wb").write(body)
PY
cmp "$TMP/part_body.bin" "$TMP/body.txt" || fail "text payload differs from the composed body"
python3 - "$TMP/part1.bin" "$TMP/note.txt" <<'PY'
import sys, base64, re
raw = open(sys.argv[1], "rb").read()
b = re.search(rb'boundary="([^"]+)"', raw).group(1)
seg = raw.split(b"--" + b + b"\r\n")[2]        # the attachment part
att = seg.split(b"\r\n\r\n", 1)[1]
att = att.split(b"\r\n--", 1)[0]                 # strip closing boundary
decoded = base64.b64decode(att)
want = open(sys.argv[2], "rb").read()
assert decoded == want, "attachment bytes differ after decode"
PY
echo "--- gate 3 PASS: text payload and attachment survive the wire byte-exactly ---"

# ---------- 5. --roundtrip through our own decrypt_mime ----------
moon run example/mailer --target native -- \
  --from "MoonBit Sender <sender@mailpgp.example>" \
  --to "MoonBit Recipient <rcpt@mailpgp.example>" \
  --subject "e2e signed encrypted mail" \
  --body-file "$TMP/body.txt" \
  --attach note.txt:"$TMP/note.txt" \
  --sender-key "$KEY" \
  --recipient-cert "$KEY" \
  --domain mailpgp.example \
  --roundtrip | tee "$TMP/roundtrip.log" | grep -q "roundtrip: signature Ok" \
  || fail "roundtrip self-check failed"
echo "--- gate 4 PASS: our own decrypt_mime verifies and collects ---"

echo "E2E PASS: composed, signed, encrypted, sent over real SMTP; gpg and moonpgp both verify."
rm -rf "$TMP"
