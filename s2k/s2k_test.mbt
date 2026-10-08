///|
/// Reference vectors computed independently from the RFC 9580 formulas
/// with Python's hashlib (passphrase "hello", salt = 00..07).
///
/// The Simple vector used to be `e3b0c442…b855` — SHA-256 of the EMPTY
/// string, i.e. a snapshot of a bug that ignored the passphrase entirely.
/// It is SHA-256("hello") now; see also the passphrase-dependence test.
test "simple s2k (sha256, 32 bytes)" {
  let s : @s2k.S2k = @s2k.Simple(@primitives.Sha256)
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  )
}

///|
/// Simple S2K must hash the passphrase itself (RFC 9580 §3.7.1.1). Every
/// passphrase deriving the same key is the observable failure mode, so pin
/// both difference and the multi-block form `H(zeros(j) ‖ passphrase)`.
test "simple s2k hashes the passphrase, not the empty string" {
  let s : @s2k.S2k = @s2k.Simple(@primitives.Sha256)
  let hello = s.derive_key(b"hello", 32)
  assert_false(hello == s.derive_key(b"world", 32))
  assert_false(hello == s.derive_key(b"", 32))
  // 48 octets = H(passphrase) ‖ first 16 octets of H(0x00 ‖ passphrase).
  assert_eq(
    @primitives.to_hex(s.derive_key(b"hello", 48)),
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" +
    "8a2a5c9b768827de5a9552c38a044c66",
  )
}

///|
/// RFC 9580 §3.7.1.3: at least one full salt‖passphrase copy is hashed
/// regardless of the encoded count, so a passphrase longer than
/// `count - salt` must not be truncated (go-crypto clamps the same way).
/// Vector: SHA-256(00..07 ‖ "a"*1100), count byte 0 (= 1024 octets), so the
/// clamp to 1108 octets is what makes it pass.
test "iterated s2k keeps a passphrase longer than the octet count" {
  let s : @s2k.S2k = @s2k.Iterated(@primitives.Sha256, test_salt(), 0)
  assert_eq(@s2k.decode_count(0), 1024)
  assert_eq(
    @primitives.to_hex(s.derive_key(Bytes::make(1100, b'a'), 32)),
    "6cf0ed4d0c1e96061c2e151dde4a54f02aae6d08b2865b5950368908d69c3912",
  )
}

///|
test "salted s2k (sha256, 32 bytes)" {
  let s : @s2k.S2k = @s2k.Salted(@primitives.Sha256, test_salt())
  let key = s.derive_key(@primitives.utf8_bytes("hello").exact_view(), 32)
  assert_eq(
    @primitives.to_hex(key),
    "f04772b55e1988558f067225a8eedde801e69e92977d39555d2d245266208862",
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
    "08807eb3305f8ca6328cee31943cec8971c195aaf3ea2f1aacb6dcf28d485bdc",
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

///|
/// RFC 9580 §3.7.1.4 type-4 wire form: `04 || salt(16) || t || p ||
/// encoded_m`, exactly 20 octets, with no hash-algorithm octet.
test "argon2 s2k wire encode/decode roundtrip" {
  let spec = @primitives.from_hex("0401020304050607080102030405060708030410")
  let (parsed, used) = @s2k.parse(spec.exact_view())
  assert_eq(used, 20)
  assert_eq(
    parsed,
    @s2k.Argon2(
      @primitives.from_hex("01020304050607080102030405060708"),
      3,
      4,
      16,
    ),
  )
  assert_eq(@primitives.to_hex(parsed.encode()), @primitives.to_hex(spec))
}

///|
/// go-crypto v1.4.1 `openpgp/s2k/s2k_test.go` vectors: specifier
/// `04 || 0102..0708_0102..0708 || 03 04 10` with passphrase "hello" and a
/// 4-octet tag (re-verified against `golang.org/x/crypto/argon2`).
test "argon2 s2k derive (go-crypto vector, T=4)" {
  let spec = @primitives.from_hex("0401020304050607080102030405060708030410")
  let (s2k, _) = @s2k.parse(spec.exact_view())
  let key = s2k.derive_key(@primitives.utf8_bytes("hello").exact_view(), 4)
  assert_eq(@primitives.to_hex(key), "dabc018a")
}

///|
/// The Argon2 parameter domain is enforced at parse *and* at encode, since
/// `S2k` is `pub(all)` and callers can build specifiers directly.
test "argon2 s2k rejects malformed parameters" {
  let salt = "01020304050607080102030405060708"
  // t = 0
  assert_s2k_parse_raises("04" + salt + "000410")
  // p = 0
  assert_s2k_parse_raises("04" + salt + "030010")
  // encoded_m = 4 -> 16 KiB < 8*4
  assert_s2k_parse_raises("04" + salt + "030404")
  // encoded_m = 32 is unrepresentable (one octet, max 31)
  assert_s2k_parse_raises("04" + salt + "030420")
  // truncated (19 octets)
  assert_s2k_parse_raises("04" + salt + "0304")
  // The smallest legal m for p=4 is 2^5.
  let (ok, used) = @s2k.parse(
    @primitives.from_hex("04" + salt + "030405").exact_view(),
  )
  assert_eq(used, 20)
  assert_eq(ok, @s2k.Argon2(@primitives.from_hex(salt), 3, 4, 5))
  // Caller-built specifiers must not encode out-of-domain parameters.
  assert_s2k_encode_raises(@s2k.Argon2(@primitives.from_hex(salt), 0, 4, 16))
  assert_s2k_encode_raises(@s2k.Argon2(@primitives.from_hex(salt), 3, 0, 16))
  assert_s2k_encode_raises(@s2k.Argon2(@primitives.from_hex(salt), 3, 4, 4))
  // An 8-octet salt is legal for types 1/3 but not for Argon2.
  assert_s2k_encode_raises(@s2k.Argon2(test_salt(), 3, 4, 16))
}

///|
test "argon2 s2k derive rejects a caller-built specifier with a short salt" {
  let bad : @s2k.S2k = @s2k.Argon2(test_salt(), 3, 4, 5)
  let raised = try {
    ignore(bad.derive_key(@primitives.utf8_bytes("pw").exact_view(), 16))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
fn assert_s2k_parse_raises(hex : String) -> Unit raise {
  let raised = try {
    ignore(@s2k.parse(@primitives.from_hex(hex).exact_view()))
    false
  } catch {
    _ => true
  }
  assert_true(raised, msg="expected s2k parse to reject \{hex}")
}

///|
fn assert_s2k_encode_raises(s : @s2k.S2k) -> Unit raise {
  let raised = try {
    ignore(s.encode())
    false
  } catch {
    _ => true
  }
  assert_true(raised, msg="expected s2k encode to reject the specifier")
}
