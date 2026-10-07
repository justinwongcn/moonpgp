///|
/// Internal GHASH checkpoints for the GCM implementation (white-box):
/// the hash subkey for the all-zero AES-128 key is a published value, the
/// TC2 ciphertext product and its second GHASH step come from an
/// independent GF(2^128) computation, and multiplying by the field
/// element 1 (0x80 00 ... 00) must be the identity.
test "gcm internal checkpoints" {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes128,
    Bytes::make(16, b'\x00').exact_view(),
  )
  let h = bc.encrypt_block(Bytes::make(16, b'\x00').exact_view())
  assert_eq(@primitives.to_hex(h), "66e94bd4ef8a2c3b884cfa59ca342b2e")
  let c = @primitives.from_hex("0388dace60b6a392f328c2b971b2fe78")
  assert_eq(
    @primitives.to_hex(gcm_mul(c.exact_view(), h.exact_view())),
    "5e2ec746917062882c85b0685353deb7",
  )
  let e0 = @primitives.from_hex("80000000000000000000000000000000")
  assert_eq(
    @primitives.to_hex(gcm_mul(e0.exact_view(), h.exact_view())),
    @primitives.to_hex(h),
  )
  let y2 = @primitives.xor_bytes(
    @primitives.from_hex("5e2ec746917062882c85b0685353deb7").exact_view(),
    @primitives.from_hex("00000000000000000000000000000080").exact_view(),
  )
  assert_eq(
    @primitives.to_hex(gcm_mul(y2.exact_view(), h.exact_view())),
    "f38cbb1ad69223dcc3457ae5b6b0f885",
  )
  let s = gcm_ghash(h.exact_view(), Bytes::new(0).exact_view(), c.exact_view())
  assert_eq(@primitives.to_hex(s), "f38cbb1ad69223dcc3457ae5b6b0f885")
}

///|
/// Chunk-layer internals for the rfc4880bis A.4 final tag: the AD must be
/// header5 || u64(index) || u64(total) and the nonce the IV with that
/// index XORed into its last 8 octets.
test "aead final-tag internals match the rfc4880bis A.4 sample" {
  let h5 = @primitives.from_hex("d40107020e")
  let total = @primitives.from_hex("0000000000000016")
  let ad = aead_ad(h5.exact_view(), 1L, total.exact_view())
  assert_eq(
    @primitives.to_hex(ad),
    "d40107020e00000000000000010000000000000016",
  )
  let iv = @primitives.from_hex("5ed2bc1e470abe8f1d644c7a6c8a56")
  let nonce = aead_chunk_nonce(iv.exact_view(), 1L)
  assert_eq(@primitives.to_hex(nonce), "5ed2bc1e470abe8f1d644c7a6c8a57")
  let key = @primitives.from_hex("d1f01ba30e130aa7d2582c16e050ae44")
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let tag = ocb_encrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    Bytes::new(0).exact_view(),
  )
  assert_eq(@primitives.to_hex(tag), "d571bcd83b20add3a08b73af15b9a098")
}
