///|
test "aes key wrap RFC 3394 B.1 (128-bit KEK, 128-bit key)" {
  let kek = @primitives.from_hex("000102030405060708090A0B0C0D0E0F")
  let data = @primitives.from_hex("00112233445566778899AABBCCDDEEFF")
  let wrapped = @cipher.aes_key_wrap(kek.view(), data.view())
  assert_eq(
    @primitives.to_hex(wrapped.view()),
    "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
  )
  let unwrapped = @cipher.aes_key_unwrap(kek.view(), wrapped.view())
  assert_eq(unwrapped, data)
}

///|
test "aes key wrap RFC 3394 B.2 (192-bit KEK, 128-bit key)" {
  let kek = @primitives.from_hex(
    "000102030405060708090A0B0C0D0E0F1011121314151617",
  )
  let data = @primitives.from_hex("00112233445566778899AABBCCDDEEFF")
  let wrapped = @cipher.aes_key_wrap(kek.view(), data.view())
  assert_eq(
    @primitives.to_hex(wrapped.view()),
    "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
  )
  let unwrapped = @cipher.aes_key_unwrap(kek.view(), wrapped.view())
  assert_eq(unwrapped, data)
}

///|
test "aes key wrap RFC 3394 B.3 (192-bit KEK, 192-bit key)" {
  let kek = @primitives.from_hex(
    "000102030405060708090A0B0C0D0E0F1011121314151617",
  )
  let data = @primitives.from_hex(
    "00112233445566778899AABBCCDDEEFF0001020304050607",
  )
  let wrapped = @cipher.aes_key_wrap(kek.view(), data.view())
  assert_eq(
    @primitives.to_hex(wrapped.view()),
    "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2",
  )
  let unwrapped = @cipher.aes_key_unwrap(kek.view(), wrapped.view())
  assert_eq(unwrapped, data)
}

///|
test "aes key unwrap rejects tampered ciphertext" {
  let kek = @primitives.from_hex("000102030405060708090A0B0C0D0E0F")
  let data = @primitives.from_hex("00112233445566778899AABBCCDDEEFF")
  let wrapped = @cipher.aes_key_wrap(kek.view(), data.view())
  let bad = wrapped.view()[0:16]
    .to_owned()
    .add(
      Bytes::from_array([
        wrapped[16],
        wrapped[17],
        wrapped[18],
        wrapped[19],
        wrapped[20],
        wrapped[21],
        wrapped[22],
        (wrapped[23].to_int() ^ 1).to_byte(),
      ]),
    )
  let ok = try? @cipher.aes_key_unwrap(kek.view(), bad.view())
  assert_true(ok.is_err())
}
