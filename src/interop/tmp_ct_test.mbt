///|
test "verify gpg cleartext signature" {
  let key = @api.PrivateKey::from_armored(
    @fs.read_file_to_string("testdata/interop_our_key.asc"),
  )
  let message = @fs.read_file_to_string("testdata/interop_gpg_cleartext.asc")
  let (text, status) = @api.verify_cleartext(message, key.to_public())
  println("CT-TEXT: \{text}")
  println("CT-STATUS-OK: \{status == @api.Ok}")
}

///|
test "make cleartext sig for gpg" {
  let key = @api.PrivateKey::from_armored(
    @fs.read_file_to_string("testdata/interop_our_key.asc"),
  )
  println("===CTS-START===")
  println(@api.sign_cleartext("moonbit cleartext\n- dash here\n", key))
  println("===CTS-END===")
}
