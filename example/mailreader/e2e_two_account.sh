#!/usr/bin/env bash
# Two-account end-to-end acceptance: 163 <-> ProtonMail, real keys, real services.
#
#   account A  user-a@example.com    RSA-4096 (v4), secret UNPROTECTED
#   account B  user-b@example.com  Ed25519 + X25519 (v4), secret S2K-locked
#
# Three gates, all through the shipped examples (example/mailer + example/mailreader):
#
#   1. A -> B live: sign with A, encrypt to B, submit via smtp.163.com:465.
#      PASS = SMTP 250 + the produced PKESK names B's cv25519 subkey
#      B-ENC-SUBKEY (B's cv25519 subkey, derived from the key file).
#   2. A -> A live closed loop: sign with A, encrypt to A, submit, fetch over
#      IMAPS, decrypt with A and verify with A. PASS = "decrypt+verify OK".
#   3. B -> A real interop: the genuine ProtonMail reply sitting in the INBOX,
#      decrypted with A and verified against B's public key.
#      PASS = "decrypt+verify OK" over mail ProtonMail itself produced.
#
# Secrets never touch argv: the 163 auth code is read from $CREDS_FILE and
# exported as $IMAP_PASS. Account B's secret is never unlocked (its passphrase
# is not known); only B's public half is used, for encryption and verification.
#
# Every path below is env-overridable; failure keeps $SINK for inspection.
set -u

cd "$(dirname "$0")/../.."

SINK="$(mktemp -d /tmp/twoaccount-e2e.XXXXXX)"

ACCOUNT_A="${ACCOUNT_A:-user-a@example.com}"
ACCOUNT_B="${ACCOUNT_B:-user-b@example.com}"
SMTP_HOST="${SMTP_HOST:-smtp.163.com}"
IMAP_HOST_NAME="${IMAP_HOST_NAME:-imap.163.com}"
CREDS_FILE="${CREDS_FILE:-$HOME/.pgp-demo/smtp-pass}"
KEY_A_PRIV="${KEY_A_PRIV:-example/user-a.asc}"
KEY_A_PUB="${KEY_A_PUB:-$HOME/.pgp-demo/addr163-pub.asc}"
KEY_B_PRIV="${KEY_B_PRIV:-example/user-b.asc}"
KEY_B_PUB="${KEY_B_PUB:-$HOME/.pgp-demo/recipient-pub.asc}"
STUNNEL_BIN="${STUNNEL_BIN:-/opt/homebrew/opt/stunnel/bin/stunnel}"
CAFILE="${CAFILE:-/opt/homebrew/etc/openssl@3/cert.pem}"
E2E_IMAP_PORT="${E2E_IMAP_PORT:-1143}"

E2E_OK=0
FAIL() {
  echo "E2E FAIL: $1 (artifacts kept in $SINK)"
  exit 1
}

cleanup() {
  if [ -n "${STUNNEL_PID:-}" ]; then
    kill "$STUNNEL_PID" 2>/dev/null || true
  fi
  if [ "$E2E_OK" = "1" ]; then
    rm -rf "$SINK"
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------- 0. preflight
for f in "$CREDS_FILE" "$KEY_A_PRIV" "$KEY_A_PUB" "$KEY_B_PRIV" "$KEY_B_PUB"; do
  [ -f "$f" ] || FAIL "missing prerequisite file: $f"
done
command -v msmtp >/dev/null || FAIL "msmtp not installed (brew install msmtp)"
command -v gpg >/dev/null || FAIL "gpg not installed"
[ -x "$STUNNEL_BIN" ] || FAIL "stunnel not found at $STUNNEL_BIN"
[ -s "$CAFILE" ] || FAIL "CA bundle not found at $CAFILE"

# B's encryption subkey: derived from B's public key file (last subkey),
# or set B_ENC_SUBKEY explicitly to override the derivation.
B_ENC_SUBKEY="${B_ENC_SUBKEY:-$(gpg --show-keys --with-colons "$KEY_B_PUB" 2>/dev/null |
  awk -F: '$1 == "sub" { id = substr($5, length($5) - 15) } END { print id }')}"
[ -n "$B_ENC_SUBKEY" ] ||
  FAIL "could not derive B's encryption subkey id from $KEY_B_PUB (set B_ENC_SUBKEY)"

# The gate-1 assertion depends on this subkey; fail loudly if the key changed.
B_SUBS="$(gpg --show-keys --with-colons "$KEY_B_PRIV" 2>/dev/null |
  awk -F: '$1 == "sub" && $12 == "e" { print toupper($5); exit }')"
[ -n "$B_SUBS" ] || FAIL "could not read B's encryption subkey from $KEY_B_PRIV"
[ "$B_SUBS" = "$B_ENC_SUBKEY" ] ||
  FAIL "B's encryption subkey changed: expected $B_ENC_SUBKEY, got $B_SUBS"
echo "--- preflight PASS: credentials + both key files present (B enc subkey $B_SUBS) ---"

# ------------------------------------------------------------ IMAPS tunnel
cat > "$SINK/stunnel.conf" <<EOF
client = yes
foreground = yes
output = $SINK/stunnel.log
[imaps]
accept = 127.0.0.1:${E2E_IMAP_PORT}
connect = ${IMAP_HOST_NAME}:993
sni = ${IMAP_HOST_NAME}
verifyChain = yes
CAfile = ${CAFILE}
checkHost = ${IMAP_HOST_NAME}
EOF
"$STUNNEL_BIN" "$SINK/stunnel.conf" &
STUNNEL_PID=$!
sleep 2
kill -0 "$STUNNEL_PID" 2>/dev/null || FAIL "stunnel failed to start (see $SINK/stunnel.log)"

IMAP_PASS="$(cat "$CREDS_FILE")"
export IMAP_PASS

submit() { # $1 = .eml to submit via real SMTP submission
  msmtp --host="$SMTP_HOST" --port=465 --tls --tls-starttls=off \
    --auth=on --user="$ACCOUNT_A" --passwordeval="cat $CREDS_FILE" \
    --read-envelope-from --read-recipients <"$1" \
    >"$SINK/msmtp-$(basename "$1").log" 2>&1 ||
    FAIL "msmtp submission failed for $1 (see $SINK/msmtp-$(basename "$1").log)"
}

reader() { # reader <args...>
  moon run example/mailreader -- \
    --imap-host 127.0.0.1 --imap-port "$E2E_IMAP_PORT" \
    --user "$ACCOUNT_A" --pass-env IMAP_PASS "$@"
}

# ------------------------------------------------- 1. A -> B: sign, encrypt
SUBJ_AB="MoonBit OpenPGP two-account A2B $(date +%s)"
cat > "$SINK/body-ab.txt" <<EOF
two-account e2e marker (A->B): $SUBJ_AB

签名:A 账号私钥(${KEY_A_PRIV##*/})
加密:B 账号公钥(cv25519 子钥 ${B_ENC_SUBKEY})
EOF
moon run example/mailer -- \
  --from "MoonBit OpenPGP Demo <${ACCOUNT_A}>" \
  --to "${ACCOUNT_B}" \
  --subject "$SUBJ_AB" \
  --body-file "$SINK/body-ab.txt" \
  --sender-key "$KEY_A_PRIV" \
  --recipient-cert "$KEY_B_PUB" \
  --domain 163.com --mode file --out "$SINK/a2b.eml" \
  >>"$SINK/compose-ab.log" 2>&1 ||
  FAIL "mailer compose A->B failed (see $SINK/compose-ab.log)"

submit "$SINK/a2b.eml"
echo "--- gate 1a PASS: A->B signed+encrypted mail accepted by $SMTP_HOST ---"

gpg --list-packets "$SINK/a2b.eml" >"$SINK/a2b.packets" 2>/dev/null || true
grep -q "keyid ${B_ENC_SUBKEY}" "$SINK/a2b.packets" ||
  FAIL "A->B PKESK does not name B's encryption subkey (see $SINK/a2b.packets)"
echo "--- gate 1b PASS: PKESK targets B's cv25519 subkey ${B_ENC_SUBKEY} ---"

# --------------------------------- 2. A -> A: full live closed loop with key A
SUBJ_AA="MoonBit OpenPGP two-account A2A $(date +%s)"
cat > "$SINK/body-aa.txt" <<EOF
two-account e2e marker (A->A): $SUBJ_AA

这封邮件用 A 账号私钥签名、A 账号公钥加密,经 smtp.163.com 提交,
再由 mailreader 经 IMAPS 取回、用同一把私钥解密并验签。
EOF
moon run example/mailer -- \
  --from "MoonBit OpenPGP Demo <${ACCOUNT_A}>" \
  --to "${ACCOUNT_A}" \
  --subject "$SUBJ_AA" \
  --body-file "$SINK/body-aa.txt" \
  --sender-key "$KEY_A_PRIV" \
  --recipient-cert "$KEY_A_PUB" \
  --domain 163.com --mode file --out "$SINK/a2a.eml" \
  >>"$SINK/compose-aa.log" 2>&1 ||
  FAIL "mailer compose A->A failed (see $SINK/compose-aa.log)"

submit "$SINK/a2a.eml"
echo "--- gate 2a PASS: A->A signed+encrypted mail accepted by $SMTP_HOST ---"

UID_AA=""
for _ in $(seq 1 15); do
  reader --last 10 >"$SINK/list-aa.txt" 2>&1 || FAIL "mailreader list failed (see $SINK/list-aa.txt)"
  UID_AA="$(grep -F "$SUBJ_AA" "$SINK/list-aa.txt" | sed -E 's/.*uid=([0-9]+).*/\1/' | tail -1)"
  [ -n "$UID_AA" ] && break
  sleep 2
done
[ -n "$UID_AA" ] || FAIL "A->A mail not visible over IMAP within the wait window"
echo "--- gate 2b PASS: A->A mail listed over IMAPS (uid=$UID_AA) ---"

mkdir -p "$SINK/out-aa"
reader --fetch "$UID_AA" --keys "$KEY_A_PRIV" --certs "$KEY_A_PUB" \
  --out "$SINK/out-aa" >"$SINK/fetch-aa.log" 2>&1 ||
  FAIL "A->A fetch+decrypt failed (see $SINK/fetch-aa.log)"
grep -q "decrypt+verify OK" "$SINK/fetch-aa.log" ||
  FAIL "A->A decrypt/verify not OK (see $SINK/fetch-aa.log)"
grep -qF "two-account e2e marker (A->A): $SUBJ_AA" "$SINK/fetch-aa.log" ||
  FAIL "A->A body marker missing after decryption (see $SINK/fetch-aa.log)"
echo "--- gate 2c PASS: A->A fetched, decrypted with A, signature verified Ok ---"

# ------------------------- 3. B -> A: genuine ProtonMail mail, real interop
UID_BA="$(reader --last 30 2>"$SINK/list-ba.err" |
  grep -i "$ACCOUNT_B" | sed -E 's/.*uid=([0-9]+).*/\1/' | tail -1)" ||
  FAIL "mailreader list failed (see $SINK/list-ba.err)"
[ -n "$UID_BA" ] || FAIL "no ProtonMail-produced mail found in the INBOX"

mkdir -p "$SINK/out-ba"
reader --fetch "$UID_BA" --keys "$KEY_A_PRIV" --certs "$KEY_B_PUB" \
  --out "$SINK/out-ba" >"$SINK/fetch-ba.log" 2>&1 ||
  FAIL "B->A fetch+decrypt failed (see $SINK/fetch-ba.log)"
grep -q "decrypt+verify OK" "$SINK/fetch-ba.log" ||
  FAIL "B->A decrypt/verify not OK (see $SINK/fetch-ba.log)"
grep -q "verify status: \[Ok\]" "$SINK/fetch-ba.log" ||
  FAIL "B->A verify status is not [Ok] (see $SINK/fetch-ba.log)"
echo "--- gate 3 PASS: real ProtonMail mail (uid=$UID_BA) decrypted with A, signature of B verified Ok ---"

E2E_OK=1
echo "E2E PASS: A->B live send, A->A live closed loop, and real ProtonMail B->A interop."
