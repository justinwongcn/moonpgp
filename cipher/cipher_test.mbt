///|
test "cfb roundtrip with random iv" {
  let key = @primitives.random_bytes(32)
  let bc = @primitives.new_block_cipher(@primitives.Aes256, key.exact_view())
  let iv = @primitives.random_bytes(16)
  let data = @primitives.random_bytes(80)
  let ct = @cipher.cfb_encrypt(bc, iv.exact_view(), data.exact_view())
  let pt = @cipher.cfb_decrypt(bc, iv.exact_view(), ct.exact_view())
  assert_eq(pt, data)
}

///|
test "cfb first block under zero iv is P0 xor E(0)" {
  // CFB: C0 = P0 XOR E(IV); with an all-zero IV, C0 = P0 XOR E(0).
  let key = @primitives.random_bytes(16)
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let zeros = Bytes::make(16, b'\x00')
  let p0 = @primitives.random_bytes(16)
  let ct = @cipher.cfb_encrypt(bc, zeros.exact_view(), p0.exact_view())
  let expected = @primitives.xor_bytes(
    p0.exact_view(),
    bc.encrypt_block(zeros.exact_view()).exact_view(),
  )
  assert_eq(ct[0:16].to_owned(), expected)
}

///|
test "cfb handles partial final block" {
  let key = @primitives.random_bytes(16)
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let zeros = Bytes::make(16, b'\x00')
  let data = @primitives.random_bytes(54)
  let ct = @cipher.cfb_encrypt(bc, zeros.exact_view(), data.exact_view())
  assert_eq(ct.length(), 54)
  let pt = @cipher.cfb_decrypt(bc, zeros.exact_view(), ct.exact_view())
  assert_eq(pt, data)
}

///|
/// Known-answer: plaintext built per RFC 9580 §5.13.1 (prefix 3031..3e3f
/// with its two repeat octets, inner "ABC...Z", 0xD3 0x14, SHA-1 MDC),
/// AES-128-CFB encrypted with an all-zero IV using OpenSSL.
test "seipd v1 known answer (openssl cross-check)" {
  let key = @primitives.from_hex("000102030405060708090a0b0c0d0e0f")
  let ciphertext = @primitives.from_hex(
    "f6900904b3ba6db55776bb599df5e64690d905ee3a3f471d425973bd4949000f358c11b74974e9643504e403476fed4179300cac8f0f3b1165607f3cc7114269331c",
  )
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let inner = @cipher.seipd_v1_decrypt(bc, ciphertext.exact_view())
  assert_eq(
    inner,
    @primitives.from_hex("4142434445464748494a4b4c4d4e4f505152535455565758595a"),
  )
  // Re-encrypting with a fresh prefix must still decrypt correctly.
  let ct2 = @cipher.seipd_v1_encrypt(bc, inner.exact_view())
  let inner2 = @cipher.seipd_v1_decrypt(bc, ct2.exact_view())
  assert_eq(inner2, inner)
}

///|
test "seipd v1 tampering is detected" {
  let key = @primitives.random_bytes(16)
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let inner = @primitives.utf8_bytes("attack at dawn")
  let ct = @cipher.seipd_v1_encrypt(bc, inner.exact_view())
  // Flip one bit in the last MDC block of the ciphertext.
  let idx = ct.length() - 21
  let tampered = ct[0:idx]
    .to_owned()
    .add(Bytes::from_array([ct[idx] ^ b'\x01']))
    .add(ct[idx + 1:ct.length()].to_owned())
  let raised = try {
    let _ = @cipher.seipd_v1_decrypt(bc, tampered.exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "seipd v1 wrong key fails quick check" {
  let key = @primitives.random_bytes(32)
  let bc = @primitives.new_block_cipher(@primitives.Aes256, key.exact_view())
  let inner = @primitives.utf8_bytes("secret")
  let ct = @cipher.seipd_v1_encrypt(bc, inner.exact_view())
  let wrong = @primitives.new_block_cipher(
    @primitives.Aes256,
    @primitives.random_bytes(32).exact_view(),
  )
  let raised = try {
    let _ = @cipher.seipd_v1_decrypt(wrong, ct.exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "resync cfb roundtrip" {
  let key = @primitives.random_bytes(32)
  let bc = @primitives.new_block_cipher(@primitives.Aes256, key.exact_view())
  let prefix = @cipher.random_prefix(16)
  let data = @primitives.random_bytes(64)
  let ct = @cipher.openpgp_cfb_encrypt_resync(
    bc,
    prefix.exact_view(),
    data.exact_view(),
  )
  // Layout: 16 (C0) + 2 (checks) + 64.
  assert_eq(ct.length(), 18 + 64)
  let pt = @cipher.openpgp_cfb_decrypt_resync(bc, ct.exact_view())
  assert_eq(pt, data)
}

///|
test "resync cfb wrong key fails quick check" {
  let key = @primitives.random_bytes(16)
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let prefix = @cipher.random_prefix(16)
  let data = @primitives.utf8_bytes("legacy")
  let ct = @cipher.openpgp_cfb_encrypt_resync(
    bc,
    prefix.exact_view(),
    data.exact_view(),
  )
  let wrong = @primitives.new_block_cipher(
    @primitives.Aes128,
    @primitives.random_bytes(16).exact_view(),
  )
  let raised = try {
    let _ = @cipher.openpgp_cfb_decrypt_resync(wrong, ct.exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
