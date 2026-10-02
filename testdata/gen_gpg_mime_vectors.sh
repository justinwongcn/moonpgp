#!/usr/bin/env bash
# Regenerates the GnuPG-created PGP/MIME interop vectors:
#   interop_gpg_mime_encrypted_signed.eml.asc  (gpg-encrypted multipart/signed
#     mail; the inner signature was created by gpg over the exact part bytes)
#   interop_gpg_mime_es.asc  (gpg --encrypt --sign over a multipart/mixed text)
#   interop_gpg_mime_tampered.eml.asc (same as vector 1 but the signed body
#     was altered before encryption -> signature must fail)
# Requires: gpg 2.4.x on PATH. The key is testdata/interop_our_key.asc
# (RSA-1024, no passphrase). Run from the openpgp/ project root.
set -euo pipefail

KEYFILE=testdata/interop_our_key.asc
export GNUPGHOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT

gpg --batch --import "$KEYFILE" >/dev/null 2>&1
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')

# --- signed part: gpg signs these exact bytes (headers + body + trailing
# CRLF; the trailing CRLF doubles as the boundary delimiter's CRLF) ---
printf 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nMime body for gpg interop.\r\nSecond line.\r\n' > part1.bin
gpg --batch --pinentry-mode loopback --detach-sign --armor --output sig.asc part1.bin
gpg --verify sig.asc part1.bin 2>&1 | grep "Good signature" >/dev/null

python3 - <<'PY'
part1 = open('part1.bin', 'rb').read()
sig = open('sig.asc', 'rb').read()
B = b'MIMEBOUND'
eml = (b'Content-Type: multipart/signed; protocol="application/pgp-signature"; '
       b'micalg=pgp-sha256; boundary="' + B + b'"\r\n\r\n'
       b'--' + B + b'\r\n' + part1 +
       b'--' + B + b'\r\n'
       b'Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"\r\n'
       b'Content-Disposition: attachment; filename="OpenPGP_signature.asc"\r\n\r\n'
       + sig + b'\r\n'
       b'--' + B + b'--\r\n')
open('signed.eml', 'wb').write(eml)
tampered = eml.replace(b'Mime body for gpg interop.', b'TAMPERED body for gpg interop.')
assert tampered != eml
open('tampered.eml', 'wb').write(tampered)

mime2 = (b'Content-Type: multipart/mixed; boundary="IDX"\r\n\r\n'
         b'--IDX\r\nContent-Type: text/plain\r\n\r\n'
         b'inline signed mime body\r\n'
         b'--IDX\r\nContent-Type: application/octet-stream; name="a.bin"\r\n'
         b'Content-Disposition: attachment; filename="a.bin"\r\n\r\n'
         b'ATTACHMENTBYTES\r\n--IDX--\r\n')
open('mime2.txt', 'wb').write(mime2)
PY

gpg --batch --yes --trust-model always --armor --encrypt --recipient "$FPR" \
    --output testdata/interop_gpg_mime_encrypted_signed.eml.asc signed.eml
gpg --batch --yes --trust-model always --armor --encrypt --recipient "$FPR" \
    --output testdata/interop_gpg_mime_tampered.eml.asc tampered.eml
gpg --batch --yes --trust-model always --armor --encrypt --sign --recipient "$FPR" \
    --output testdata/interop_gpg_mime_es.asc mime2.txt

rm -f part1.bin sig.asc signed.eml tampered.eml mime2.txt
echo "vectors written:"
ls -la testdata/interop_gpg_mime_*
