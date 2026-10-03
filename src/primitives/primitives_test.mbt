///|
test "sha256 digest (RFC 6234 / FIPS 180 'abc' vector)" {
  let d = @primitives.Sha256.digest(b"abc")
  assert_eq(
    @primitives.to_hex(d),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "sha1 digest" {
  let d = @primitives.Sha1.digest(b"abc")
  assert_eq(@primitives.to_hex(d), "a9993e364706816aba3e25717850c26c9cd0d89d")
}

///|
test "ripemd160 digest" {
  let d = @primitives.Ripemd160.digest(b"abc")
  assert_eq(@primitives.to_hex(d), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
}

///|
test "hmac-sha256 (RFC 4231 case 2)" {
  let key = b"Jefe"
  let data = b"what do ya want for nothing?"
  let d = @primitives.Sha256.hmac(key, data)
  assert_eq(
    @primitives.to_hex(d),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
}

///|
test "aes block roundtrip via trait object" {
  let key = @primitives.random_bytes(32)
  let cipher = @primitives.new_block_cipher(
    @primitives.Aes256,
    key.exact_view(),
  )
  let block = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let enc = cipher.encrypt_block(block.exact_view())
  assert_eq(enc.length(), 16)
  assert_false(enc.equal(block))
  let dec = cipher.decrypt_block(enc.exact_view())
  assert_true(dec.equal(block))
}

///|
test "random_bytes length and uniqueness" {
  let a = @primitives.random_bytes(32)
  let b = @primitives.random_bytes(32)
  assert_eq(a.length(), 32)
  assert_false(a.equal(b))
}

///|
test "ct_equal" {
  assert_true(@primitives.ct_equal(b"abcd", b"abcd"))
  assert_false(@primitives.ct_equal(b"abcd", b"abce"))
  assert_false(@primitives.ct_equal(b"abc", b"abcd"))
}
