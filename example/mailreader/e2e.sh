#!/usr/bin/env bash
# example/mailreader e2e: the full closed loop against a real mailbox.
#
#   1. compose + sign + encrypt a fresh mail with example/mailer and
#      submit it via msmtp to OUR OWN mailbox (real SMTP, TLS via msmtp)
#   2. wait for delivery, list the mailbox over IMAP with
#      example/mailreader (two transports supported:
#        default    plaintext 143 + --allow-insecure   [decision 2]
#        E2E_TUNNEL=1  local stunnel -> IMAPS 993)
#   3. locate the fresh mail by its unique subject, fetch it by UID and
#      decrypt+verify through @mime.decrypt_mime
#   4. assert the four-state result, the body marker and the saved .eml
#
# Failure keeps every artifact under $SINK for inspection.
set -u

cd "$(dirname "$0")/../.."

SINK="$(mktemp -d /tmp/mailreader-e2e.XXXXXX)"
IMAP_HOST_NAME="${IMAP_HOST_NAME:-imap.163.com}"
IMAP_USER="${IMAP_USER:-user-a@example.com}"
CREDS_FILE="${CREDS_FILE:-$HOME/.pgp-demo/smtp-pass}"
SENDER_KEY="${SENDER_KEY:-$HOME/.pgp-demo/sender-key.asc}"
SENDER_PUB="${SENDER_PUB:-$HOME/.pgp-demo/sender-pub.asc}"
KEY163_PRIV="${KEY163_PRIV:-example/user-a.asc}"
KEY163_PUB="${KEY163_PUB:-$HOME/.pgp-demo/addr163-pub.asc}"
STUNNEL_BIN="${STUNNEL_BIN:-/opt/homebrew/opt/stunnel/bin/stunnel}"

E2E_OK=0
FAIL() {
  echo "E2E FAIL: $1 (artifacts kept in $SINK)"
  exit 1
}

# failure keeps the whole workspace for debugging; success removes it
cleanup() {
  if [ -n "${STUNNEL_PID:-}" ]; then
    kill "$STUNNEL_PID" 2>/dev/null || true
  fi
  if [ "$E2E_OK" = "1" ]; then
    rm -rf "$SINK"
  fi
}
trap cleanup EXIT

for f in "$CREDS_FILE" "$SENDER_KEY" "$SENDER_PUB" "$KEY163_PRIV" "$KEY163_PUB"; do
  [ -f "$f" ] || FAIL "missing prerequisite file: $f"
done
command -v msmtp >/dev/null || FAIL "msmtp not installed (brew install msmtp)"

# ---------------------------------------------------------------- 1. send
SUBJECT="MoonBit OpenPGP e2e fetch round trip $(date +%s)"
cat > "$SINK/body.txt" <<EOF
mailreader e2e marker: $SUBJECT

这封邮件由 example/mailer 签名并加密、经 msmtp 提交,
再由 example/mailreader 通过 IMAP 取回、解密并验签。
EOF

moon run example/mailer -- \
  --from "MoonBit OpenPGP Demo <${IMAP_USER}>" \
  --to "${IMAP_USER}" \
  --subject "$SUBJECT" \
  --body-file "$SINK/body.txt" \
  --sender-key "$SENDER_KEY" \
  --recipient-cert "$KEY163_PUB" \
  --domain 163.com \
  --mode file --out "$SINK/mail.eml" >>"$SINK/send.log" 2>&1 \
  || FAIL "mailer compose failed (see $SINK/send.log)"

msmtp --host=smtp.163.com --port=465 --tls --tls-starttls=off \
  --auth --user="$IMAP_USER" --passwordeval="cat $CREDS_FILE" \
  --read-envelope-from --read-recipients <"$SINK/mail.eml" \
  >"$SINK/msmtp.log" 2>&1 \
  || FAIL "msmtp submission failed (see $SINK/msmtp.log)"
echo "--- gate 1 PASS: fresh signed+encrypted mail accepted by smtp.163.com ---"

# --------------------------------------------------------------- 2. reader
IMAP_ADDR="$IMAP_HOST_NAME"
IMAP_FLAGS=""
IMAP_PORT=143
if [ "${E2E_TUNNEL:-0}" = "1" ]; then
  [ -x "$STUNNEL_BIN" ] || FAIL "stunnel not found at $STUNNEL_BIN"
  cat > "$SINK/stunnel.conf" <<EOF
client = yes
foreground = yes
[imaps]
accept = 127.0.0.1:1143
connect = ${IMAP_HOST_NAME}:993
sni = ${IMAP_HOST_NAME}
verifyChain = yes
CAfile = /opt/homebrew/etc/openssl@3/cert.pem
checkHost = ${IMAP_HOST_NAME}
EOF
  "$STUNNEL_BIN" "$SINK/stunnel.conf" &
  STUNNEL_PID=$!
  sleep 2
  IMAP_ADDR="127.0.0.1"
  IMAP_PORT=1143
else
  IMAP_ADDR="$(dig +short "$IMAP_HOST_NAME" | tail -1)"
  case "$IMAP_ADDR" in
    ""|*[!0-9.]*) FAIL "could not resolve $IMAP_HOST_NAME to a dotted quad (is dig installed?)" ;;
  esac
  IMAP_FLAGS="--allow-insecure"
fi

export IMAP_PASS
IMAP_PASS="$(cat "$CREDS_FILE")"

MSG_UID=""
for i in $(seq 1 15); do
  moon run example/mailreader -- \
    --imap-host "$IMAP_ADDR" --imap-port "${E2E_IMAP_PORT:-$([ "${E2E_TUNNEL:-0}" = "1" ] && echo 1143 || echo 143)}" \
    --imap-port "${E2E_IMAP_PORT:-$IMAP_PORT}" \
    --user "$IMAP_USER" --pass-env IMAP_PASS --last 10 \
    $IMAP_FLAGS >"$SINK/list.txt" 2>&1 \
    || FAIL "mailreader list failed (see $SINK/list.txt)"
  grep -q "seq=" "$SINK/list.txt" || FAIL "list produced no rows"
  MSG_UID="$(grep -F "$SUBJECT" "$SINK/list.txt" | sed -E 's/.*uid=([0-9]+).*/\1/' | tail -1)"
  [ -n "$MSG_UID" ] && break
  sleep 2
done
[ -n "$MSG_UID" ] || FAIL "fresh mail not seen in the mailbox within the wait window"
echo "--- gate 2 PASS: mail listed over IMAP, located by unique subject (uid=$MSG_UID) ---"

# ------------------------------------------------- 3. fetch + decrypt
moon run example/mailreader -- \
  --imap-host "$IMAP_ADDR" --imap-port "${E2E_IMAP_PORT:-$IMAP_PORT}" \
  --user "$IMAP_USER" --pass-env IMAP_PASS --fetch "$MSG_UID" \
  --keys "$KEY163_PRIV" --certs "$SENDER_PUB" \
  --out "$SINK" $IMAP_FLAGS >"$SINK/fetch.log" 2>&1 \
  || FAIL "fetch+decrypt failed (see $SINK/fetch.log)"

# --------------------------------------------------------------- 4. gates
grep -q "decrypt+verify OK" "$SINK/fetch.log" \
  || FAIL "decrypt/verify did not end OK (see $SINK/fetch.log)"
grep -qF "mailreader e2e marker: $SUBJECT" "$SINK/fetch.log" \
  || FAIL "body marker missing after decryption (see $SINK/fetch.log)"
[ -s "$SINK/msg-$MSG_UID.eml" ] || FAIL "fetched .eml missing or empty"
echo "--- gate 3 PASS: fetched by UID, decrypt_mime verified Ok, body marker present ---"

E2E_OK=1
rm -rf "$SINK"
echo "E2E PASS: sent via mailer+msmtp, fetched via mailreader, decrypt_mime verified."
