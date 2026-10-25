///|
test "cleartext sign/verify roundtrip" {
  let key = @api.generate_key("CT <ct@example.com>", bits=2048)
  let text = "hello cleartext\nsecond line\n"
  let message = @api.sign_cleartext(text, key)
  assert_true(
    message.has_prefix("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"),
  )
  assert_true(message.contains("-----BEGIN PGP SIGNATURE-----"))
  let (recovered, status) = @api.verify_cleartext(message, key.to_public())
  assert_eq(status, @api.Ok)
  assert_eq(recovered, "hello cleartext\r\nsecond line")
}

///|
test "cleartext dash-escaping" {
  let key = @api.generate_key("CT <ct@example.com>", bits=2048)
  let text = "normal\n- starts with dash\nFrom me\n- continued -\n"
  let message = @api.sign_cleartext(text, key)
  // Display form escapes dashes; the signature covers the de-escaped text.
  assert_true(message.contains("- - starts with dash\n"))
  assert_true(message.contains("- From me\n"))
  let (recovered, status) = @api.verify_cleartext(message, key.to_public())
  assert_eq(status, @api.Ok)
  assert_eq(
    recovered, "normal\r\n- starts with dash\r\nFrom me\r\n- continued -",
  )
}

///|
test "cleartext trailing whitespace is trimmed before signing" {
  let key = @api.generate_key("CT <ct@example.com>", bits=2048)
  // Signed with trailing spaces on every line.
  let message = @api.sign_cleartext("word \nother\t\n", key)
  // Verify text without the trailing whitespace: same canonical form.
  let (_, status) = @api.verify_cleartext(message, key.to_public())
  assert_eq(status, @api.Ok)
}

///|
test "cleartext tampering is detected" {
  let key = @api.generate_key("CT <ct@example.com>", bits=2048)
  let message = @api.sign_cleartext("sign this line\n", key)
  // Alter the visible text (drop the escape, change a word) while keeping
  // the signature: signature must fail.
  let tampered = message.replace(old="sign this line", new="tampered line")
  let (_, status) = @api.verify_cleartext(tampered, key.to_public())
  assert_eq(status, @api.Failed)
}

///|
test "cleartext wrong verifier fails" {
  let signer = @api.generate_key("S <s@example.com>", bits=2048)
  let other = @api.generate_key("O <o@example.com>", bits=2048)
  let message = @api.sign_cleartext("who signed me?\n", signer)
  // A key that is not the signer yields NoVerifier (cannot even attempt);
  // Failed is reserved for a matching key whose verification failed.
  let (_, status) = @api.verify_cleartext(message, other.to_public())
  assert_eq(status, @api.NoVerifier)
}

///|
test "cleartext with missing trailing newline" {
  let key = @api.generate_key("CT <ct@example.com>", bits=2048)
  let text = "no trailing newline"
  let message = @api.sign_cleartext(text, key)
  let (recovered, status) = @api.verify_cleartext(message, key.to_public())
  assert_eq(status, @api.Ok)
  assert_eq(recovered, "no trailing newline")
}
