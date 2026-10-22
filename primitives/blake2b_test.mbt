///|
/// BLAKE2b reference vectors (RFC 7693 Appendix A, plus block-boundary and
/// shortened-digest cases from the research brief §4.4, cross-checked with
/// `golang.org/x/crypto/blake2b`).
test "blake2b-512 empty string" {
  let d = @primitives.blake2b(b"", 64)
  assert_eq(
    @primitives.to_hex(d),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  )
}

///|
test "blake2b-512 abc (RFC 7693 Appendix A)" {
  let d = @primitives.blake2b(b"abc", 64)
  assert_eq(
    @primitives.to_hex(d),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  )
}

///|
test "blake2b-512 quick brown fox" {
  let msg = @primitives.utf8_bytes(
    "The quick brown fox jumps over the lazy dog",
  )
  let d = @primitives.blake2b(msg, 64)
  assert_eq(
    @primitives.to_hex(d),
    "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
  )
}

///|
/// "abc" followed by 125 zero octets is exactly one 128-byte block: the
/// finalization path must count the real length, not the padded length.
test "blake2b-512 abc + 125 zeros (exactly 128 bytes)" {
  let d = @primitives.blake2b(padded_abc(125), 64)
  assert_eq(
    @primitives.to_hex(d),
    "76d22d522b7c3c1e50a2f9839b451d7feaeb82850d5cc0353ff719b4d936686c8ddf46746e4ab16dd0ed69f2ae55151b0066b0e85f57819df96ac7ad2d698bc7",
  )
}

///|
test "blake2b-512 abc + 126 zeros (exactly 129 bytes, two blocks)" {
  let d = @primitives.blake2b(padded_abc(126), 64)
  assert_eq(
    @primitives.to_hex(d),
    "3bd2f2a9bb9940e95121c067bcca12faf409b46331856160905e7ba16ee9cc21f8ca75b12dd8606d2ef4dd6dac61028c9c41034e73195f11f2daec3c6352c782",
  )
}

///|
test "blake2b shortened digests (nn=32, nn=16)" {
  assert_eq(
    @primitives.to_hex(@primitives.blake2b(b"abc", 32)),
    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
  )
  // A shorter digest length is a *parameter*, not a truncation: BLAKE2b-128
  // of "abc" is not a prefix of BLAKE2b-256 of "abc". (The research brief
  // §4.4 listed the truncated value here; Python's hashlib agrees with the
  // value below.)
  assert_eq(
    @primitives.to_hex(@primitives.blake2b(b"abc", 16)),
    "cf4ab791c62b8d2b2109c90275287816",
  )
  assert_eq(
    @primitives.to_hex(@primitives.blake2b(b"", 32)),
    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
  )
  assert_eq(
    @primitives.to_hex(@primitives.blake2b(b"", 16)),
    "cae66941d9efbd404e4d88758ea67670",
  )
}

///|
test "blake2b rejects an out-of-range digest length" {
  // `fail` used to sit inside the `try`, so the `catch` swallowed it and
  // these assertions could never fire.
  for n in [0, 65] {
    let raised = try {
      ignore(@primitives.blake2b(b"abc", n))
      false
    } catch {
      @error.PgpError(msg~) => {
        assert_true(msg.contains("digest length"))
        true
      }
      _ => fail("expected a PgpError for out_len=\{n}")
    }
    assert_true(raised, msg="blake2b(out_len=\{n}) must raise")
  }
}

///|
/// `"abc"` followed by `n` zero octets.
fn padded_abc(n : Int32) -> Bytes {
  let out : Array[Byte] = [b'a', b'b', b'c']
  for _ in 0..<n {
    out.push(b'\x00')
  }
  Bytes::from_array(out)
}
