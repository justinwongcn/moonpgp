// Cleanup round (2026-11-13), E3: MIME-aware payload extraction.

///|
/// A decoy PUBLIC KEY armor part placed BEFORE the real
/// multipart/encrypted container must not hijack the decryption: the
/// whole-text first-block scan used to feed the decoy to the PGP layer
/// and fail delivery of the perfectly decryptable message.
test "decrypt_mime is not hijacked by a decoy armor part (E3)" {
  let payload = @api.encrypt_with_password(b"payload body\n", "passphrase-1")
  let decoy_key = @api.generate_ed25519_key("Decoy <decoy@example.net>")
  let decoy = decoy_key.to_public().to_armored()
  let mail = "Content-Type: multipart/mixed; boundary=MMIX\r\n\r\n" +
    "--MMIX\r\nContent-Type: application/pgp-keys\r\n\r\n" +
    decoy +
    "\r\n--MMIX\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=PENC\r\n\r\n" +
    "--PENC\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n" +
    "--PENC\r\nContent-Type: application/octet-stream\r\n\r\n" +
    payload +
    "\r\n--PENC--\r\n--MMIX--\r\n"
  let cb = new_callbacks()
  @mime.decrypt_mime(
    mail,
    [],
    verifiers=[],
    callbacks=cb,
    password="passphrase-1",
  )
  assert_eq(cb.errors, [])
  assert_eq(cb.bodies, [("payload body\n", "text/plain")])
}

///|
/// Control: bare armored input (no MIME wrapper) still decrypts through
/// the fallback path.
test "bare armored message still decrypts (E3 fallback)" {
  let payload = @api.encrypt_with_password(b"plain armored\n", "pw")
  let cb = new_callbacks()
  @mime.decrypt_mime(payload, [], verifiers=[], callbacks=cb, password="pw")
  assert_eq(cb.errors, [])
  assert_eq(cb.bodies, [("plain armored\n", "text/plain")])
}
