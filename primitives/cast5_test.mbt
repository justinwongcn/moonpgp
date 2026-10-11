///|
/// CAST5 known-answer tests: RFC 2144 Appendix B.1 (128-bit key) plus
/// single-block ECB vectors cross-checked against OpenSSL 3.6.3
/// (`openssl enc -cast5-ecb -provider legacy`).

///|
test "CAST5 RFC 2144 B.1 128-bit known answer" {
  let key = @primitives.from_hex("0123456712345678234567893456789A")
  let pt = @primitives.from_hex("0123456789ABCDEF")
  let expected = @primitives.from_hex("238B4FE5847E44B2")
  let bc = @primitives.new_cast5(key.exact_view())
  assert_eq(bc.block_size(), 8)
  let ct = bc.encrypt_block(pt.exact_view())
  assert_eq(ct, expected)
  // Decryption inverts it (Feistel with reversed subkeys).
  assert_eq(bc.decrypt_block(ct.exact_view()), pt)
}

///|
test "CAST5 ECB vectors from OpenSSL (two blocks each)" {
  // openssl enc -cast5-ecb -provider legacy over the 8-octet plaintext
  // "testtest" (two identical blocks — also proves block independence).
  let key1 = @primitives.from_hex("0123456789ABCDEF0123456789ABCDEF")
  let key2 = @primitives.from_hex("FEDCBA9876543210FEDCBA9876543210")
  let pt = @primitives.utf8_bytes("testtest")
  let bc1 = @primitives.new_cast5(key1.exact_view())
  assert_eq(
    @primitives.to_hex(bc1.encrypt_block(pt.exact_view()).exact_view()),
    "c5695094ed6e2078",
  )
  let bc2 = @primitives.new_cast5(key2.exact_view())
  assert_eq(
    @primitives.to_hex(bc2.encrypt_block(pt.exact_view()).exact_view()),
    "49b85f39ec266aee",
  )
  // Both decrypt back.
  assert_eq(
    bc1.decrypt_block(@primitives.from_hex("c5695094ed6e2078").exact_view()),
    pt,
  )
  assert_eq(
    bc2.decrypt_block(@primitives.from_hex("49b85f39ec266aee").exact_view()),
    pt,
  )
}

///|
test "CAST5 key must be 16 octets" {
  let raised = try {
    let _ = @primitives.new_cast5(@primitives.from_hex("00112233").exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
