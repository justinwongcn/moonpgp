///|
/// RFC 9580 §5.1.2: the v6 PKESK size octet covers the key-version and
/// fingerprint fields, and the fingerprint length follows from the key
/// version (20 octets for a v4 key, 32 for v5/v6). A size of 1 — version
/// present, fingerprint absent — used to be accepted and then re-serialized
/// as size 0, silently dropping the key version on an import/export round
/// trip.

///|
/// A v6 PKESK body: version | size | [key-version | fingerprint] | pubalgo |
/// MPI. RSA is used for the payload because an MPI is a fixed, trivial
/// encoding to build by hand.
fn v6_pkesk_body(size : Int, key_version : Int, fingerprint_len : Int) -> Bytes {
  let w = @packet.Writer::new()
  w.u8(6)
  w.u8(size)
  if size > 0 {
    w.u8(key_version)
    w.bytes(Bytes::make(fingerprint_len, b'\x03').exact_view())
  }
  w.u8(1) // RSA (RsaEncryptOrSign)
  w.mpi(Bytes::from_array([b'\x01']).exact_view())
  w.to_bytes()
}

///|
test "a v6 PKESK fingerprint size must match its key version" {
  // Anonymous recipient: size 0, both fields absent.
  let anon = @packet.PkeskPacket::parse(v6_pkesk_body(0, 0, 0).exact_view())
  assert_eq(anon.version(), 6)
  assert_eq(anon.fingerprint().length(), 0)
  // v4 key referenced from a v6 PKESK: a 20-octet fingerprint.
  let v4 = @packet.PkeskPacket::parse(v6_pkesk_body(21, 4, 20).exact_view())
  assert_eq(v4.key_version(), 4)
  assert_eq(v4.fingerprint().length(), 20)
  // v6 key: a 32-octet fingerprint.
  let v6 = @packet.PkeskPacket::parse(v6_pkesk_body(33, 6, 32).exact_view())
  assert_eq(v6.key_version(), 6)
  assert_eq(v6.fingerprint().length(), 32)
  // Malformed sizes must be rejected rather than mis-parsed.
  for pair in [(1, 4, 0), (21, 6, 20), (33, 4, 32), (2, 4, 1)] {
    let (size, key_version, fp_len) = pair
    try
      @packet.PkeskPacket::parse(
        v6_pkesk_body(size, key_version, fp_len).exact_view(),
      )
    catch {
      @error.PgpError(msg~) =>
        assert_true(msg.contains("does not match key version"))
      _ => fail("expected a PgpError for the malformed size")
    } noraise {
      _ => fail("size \{size} with key version \{key_version} was accepted")
    }
  }
}
