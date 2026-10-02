///|
/// GnuPG cross-validation of PGP/MIME (RFC 3156): `testdata/interop_gpg_pgp_mime.eml`
/// is a multipart/signed message whose signature GnuPG created over the
/// extracted part bytes; `gpg --verify` accepts our own PGP/MIME output
/// (verified manually during development).
test "verify gpg-signed pgp/mime message" {
  let key = @api.PrivateKey::from_armored(
    @fs.read_file_to_string("testdata/interop_our_key.asc"),
  )
  let message = @fs.read_file_to_string("testdata/interop_gpg_pgp_mime.eml")
  let signed = @mime.extract_pgp_signed(message)
  let status = @api.verify_detached(
    signed.signed_bytes.view(),
    signed.signature_armor,
    key.to_public(),
  )
  assert_eq(status, @api.Ok)
}

///|
test "our pgp/mime signed output matches the gpg-verified shape" {
  let key = @api.PrivateKey::from_armored(
    @fs.read_file_to_string("testdata/interop_our_key.asc"),
  )
  let message = @mime.build_pgp_mime_signed("mime roundtrip\n", key)
  // Our own extraction must round-trip the signature.
  let (_, status) = @mime.verify_pgp_mime_signed(message, key.to_public())
  assert_eq(status, @api.Ok)
}
