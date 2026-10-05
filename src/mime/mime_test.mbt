///|
test "pgp/mime signed roundtrip" {
  let key = @api.generate_key("Mime <m@example.com>", bits=1024)
  let text = "PGP/MIME signed body\nsecond line\n"
  let message = @mime.build_pgp_mime_signed(text, key)
  assert_true(message.contains("multipart/signed"))
  assert_true(message.contains("micalg=pgp-sha256"))
  let (recovered, status) = @mime.verify_pgp_mime_signed(
    message,
    key.to_public(),
  )
  assert_eq(status, @api.Ok)
  // The extracted signed entity is the text/plain part with headers.
  assert_true(recovered.contains("Content-Type: text/plain; charset=utf-8"))
  assert_true(recovered.contains("PGP/MIME signed body"))
}

///|
test "pgp/mime signed tampering detected" {
  let key = @api.generate_key("Mime <m@example.com>", bits=1024)
  let message = @mime.build_pgp_mime_signed("authentic body\n", key)
  let tampered = message.replace(old="authentic body", new="tampered body")
  let (_, status) = @mime.verify_pgp_mime_signed(tampered, key.to_public())
  assert_eq(status, @api.Failed)
}

///|
test "pgp/mime signed roundtrip without trailing newline" {
  // F04: the builder used to sign the entity without the trailing CRLF
  // that extract_pgp_signed restores, so text without a trailing newline
  // failed its own verification.
  let key = @api.generate_key("Mime <m@example.com>", bits=1024)
  let message = @mime.build_pgp_mime_signed(
    "body without trailing newline", key,
  )
  let (recovered, status) = @mime.verify_pgp_mime_signed(
    message,
    key.to_public(),
  )
  assert_eq(status, @api.Ok)
  assert_true(recovered.contains("body without trailing newline"))
}

///|
test "pgp/mime encrypted roundtrip" {
  let key = @api.generate_key("Mime <m@example.com>", bits=1024)
  let plaintext = @primitives.utf8_bytes("encrypted mime payload\n")
  let armored = @api.encrypt_to_recipients(plaintext, [key.to_public()])
  let message = @mime.build_pgp_mime_encrypted(armored)
  assert_true(message.contains("multipart/encrypted"))
  assert_true(message.contains("application/pgp-encrypted"))
  assert_true(message.contains("Version: 1"))
  // Extract and decrypt through the PGP path.
  let extracted = @mime.extract_pgp_encrypted(message)
  assert_eq(extracted, armored)
  let data = @api.decrypt_with_private_key(extracted, key)
  assert_eq(data, plaintext)
}

///|
test "password-encrypted pgp/mime roundtrip" {
  let plaintext = @primitives.utf8_bytes("password protected mime")
  let armored = @api.encrypt_with_password(plaintext, "mime pass")
  let message = @mime.build_pgp_mime_encrypted(armored)
  let extracted = @mime.extract_pgp_encrypted(message)
  assert_eq(@api.decrypt_with_password(extracted, "mime pass"), plaintext)
}

///|
test "mime header parsing with folding" {
  let msg = @mime.parse_message(
    "Content-Type: multipart/mixed;\n boundary=\"abc=123\"\nSubject: hi\n\nbody",
  )
  let ct = msg.header("content-type")
  assert_true(ct is Some(_))
  match @mime.content_type_boundary(ct.unwrap()) {
    Some(b) => assert_eq(b, "abc=123")
    None => assert_true(false)
  }
  assert_eq(msg.header("Subject"), Some("hi"))
  assert_true(msg.body.has_prefix("body"))
}

///|
test "quoted and unquoted boundary extraction" {
  assert_eq(
    @mime.content_type_boundary("multipart/mixed; boundary=\"xyz\""),
    Some("xyz"),
  )
  assert_eq(
    @mime.content_type_boundary(
      "multipart/mixed; boundary=plain; charset=utf-8",
    ),
    Some("plain"),
  )
  assert_eq(@mime.content_type_boundary("text/plain"), None)
}
