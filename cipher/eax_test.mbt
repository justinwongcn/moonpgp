///|
/// RFC 9580 Appendix A.9.2: EAX decryption of the sample v6 SKESK's
/// encrypted session key with the published AEAD key, nonce and
/// associated data.
test "eax decrypts the RFC 9580 A.9.2 session key" {
  let key = @primitives.from_hex("2fce331f39dd955cc41e95d870c72139")
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let cipher = @primitives.from_hex(
    "c5efc5f41c57fb54e1c226815d7828f5f92c454eb65ebe00ab5986c68e6e7c55",
  )
  let plain = @cipher.eax_decrypt(
    bc,
    @primitives.from_hex("69224f919993b3506fa3b59a6a73cff8").exact_view(),
    @primitives.from_hex("c3060701").exact_view(),
    cipher.exact_view(),
  )
  assert_eq(@primitives.to_hex(plain), "3881bafe985412459b86c36f98cb9a5e")
}

///|
test "eax round trip and tag rejection" {
  let key = @primitives.from_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let nonce = @primitives.from_hex("000102030405060708090a0b0c0d0e0f")
  let ad = @primitives.utf8_bytes("header")
  for msg in [b"", b"x", b"0123456789abcdef", b"0123456789abcdefg"] {
    let ct = @cipher.eax_encrypt(bc, nonce.exact_view(), ad.exact_view(), msg)
    assert_eq(ct.length(), msg.length() + 16)
    assert_eq(
      @cipher.eax_decrypt(
        bc,
        nonce.exact_view(),
        ad.exact_view(),
        ct.exact_view(),
      ),
      msg,
    )
  }
  // A flipped tag bit must fail.
  let ct = @cipher.eax_encrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    b"payload",
  )
  let tampered = ct.to_array()
  tampered[ct.length() - 1] = (tampered[ct.length() - 1].to_int() ^ 1).to_byte()
  let raised = try {
    ignore(
      @cipher.eax_decrypt(
        bc,
        nonce.exact_view(),
        ad.exact_view(),
        Bytes::from_array(tampered).exact_view(),
      ),
    )
    false
  } catch {
    @error.Malformed(msg~) => {
      assert_true(msg.contains("tag mismatch"))
      true
    }
    _ => fail("expected a PgpError from the EAX tag check")
  }
  assert_true(raised)
}
