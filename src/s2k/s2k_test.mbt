///|
/// Reference vectors computed independently from the RFC 9580 formulas
/// with Python's hashlib (passphrase "hello", salt = 00..07).
test "simple s2k (sha256, 32 bytes)" {
  let s : @s2k.S2k = @s2k.Simple(@primitives.Sha256)
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "salted s2k (sha256, 32 bytes)" {
  let s : @s2k.S2k = @s2k.Salted(@primitives.Sha256, test_salt())
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "93faebb74ad5d42366372674d76b48c7e08bfe67347a9aa796a784de5b8647bc",
  )
}

///|
test "iterated s2k (sha256, 32 bytes, count byte 96)" {
  // count = (16 + 0) << (6 + 6) = 65536
  let s : @s2k.S2k = @s2k.Iterated(@primitives.Sha256, test_salt(), 96)
  assert_eq(@s2k.decode_count(96), 65536)
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "ccd21933a8b0e1151a47439aa61b6155d1af2cddac59d179c063aabbba516156",
  )
}

///|
test "iterated s2k (sha256, 16 bytes, count byte 104)" {
  // count = (16 + 8) << (6 + 6) = 98304
  let s : @s2k.S2k = @s2k.Iterated(@primitives.Sha256, test_salt(), 104)
  assert_eq(@s2k.decode_count(104), 98304)
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 16)
  assert_eq(@primitives.to_hex(key), "8ef2a6c2f88ef582a6201eeeeb90153e")
}

///|
test "iterated s2k (sha1, 32 bytes, count byte 224)" {
  // count = (16 + 0) << (14 + 6) = 16777216
  let s : @s2k.S2k = @s2k.Iterated(@primitives.Sha1, test_salt(), 224)
  assert_eq(@s2k.decode_count(224), 16777216)
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "e36e518d21b05999be82b89f92a147aab402e7e8d80eb93cf764604a91089ed0",
  )
}

///|
test "salted s2k (sha512, 32 bytes)" {
  let s : @s2k.S2k = @s2k.Salted(@primitives.Sha512, test_salt())
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "e71efef4f8992308f24dc7377aad9758b7bcaabec95894ca2877d5190ed3e59f",
  )
}

///|
test "s2k wire encode/decode roundtrip" {
  let cases : Array[@s2k.S2k] = [
    @s2k.Simple(@primitives.Sha256),
    @s2k.Salted(@primitives.Sha256, test_salt()),
    @s2k.Iterated(@primitives.Sha256, test_salt(), 96),
  ]
  for s in cases {
    let wire = s.encode()
    let (parsed, used) = @s2k.parse(wire.exact_view())
    assert_eq(used, wire.length())
    assert_eq(parsed, s)
    let a = s.derive_key(@primitives.utf8_bytes("pw").exact_view(), 32)
    let b = parsed.derive_key(@primitives.utf8_bytes("pw").exact_view(), 32)
    assert_eq(a, b)
  }
}

///|
test "encode_count reaches target" {
  let c = @s2k.encode_count(1024 * 1024)
  assert_true(@s2k.decode_count(c) >= 1024 * 1024)
  // Monotonicity of the mapping.
  assert_true(@s2k.decode_count(0) <= @s2k.decode_count(255))
}

///|
fn test_salt() -> Bytes {
  Bytes::from_array([0, 1, 2, 3, 4, 5, 6, 7])
}

///|
test "s2k encode rejects malformed salt instead of aborting" {
  // S2k is pub(all): a caller-constructed specifier with a wrong-length
  // salt must raise like derive_key does, not kill the process.
  let bad : @s2k.S2k = @s2k.Salted(
    @primitives.Sha256,
    Bytes::from_array([b'\x01', b'\x02']),
  )
  let raised = try {
    let _ = bad.encode()
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  let bad_iterated : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    Bytes::new(0),
    96,
  )
  let raised2 = try {
    let _ = bad_iterated.encode()
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
}
