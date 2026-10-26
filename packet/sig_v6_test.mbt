///|
/// RFC 9580 §5.2.3.3.1: "Ed25519Legacy MUST NOT be used in Signature
/// packets version 6 or above"; §5.2.3.4: a v6 Ed25519 signature value is
/// exactly 64 octets. Both were accepted silently, leaving the rejection to
/// the API-layer verifier.

///|
/// A minimal v6 signature body: version | type | pubalgo | hashalgo |
/// hashed area (4-octet length) | unhashed area (4-octet length) | hash tag
/// | salt length + 16-octet salt | algorithm-specific parameters.
fn v6_signature_body(pub_algo : Int32, params : BytesView) -> Bytes {
  let w = @packet.Writer::new()
  w.u8(6)
  w.u8(0) // binary document signature
  w.u8(pub_algo)
  w.u8(8) // SHA-256, whose v6 salt is 16 octets
  w.u32(0) // hashed subpacket area
  w.u32(0) // unhashed subpacket area
  w.u16(0) // hash tag
  w.u8(16)
  w.bytes(Bytes::make(16, b'\x07').exact_view())
  w.bytes(params)
  w.to_bytes()
}

///|
test "a v6 signature rejects Ed25519Legacy and a wrong Ed25519 length" {
  // Ed25519 (27) with 64 octets parses.
  let ok = @packet.SignaturePacket::parse(
    v6_signature_body(27, Bytes::make(64, b'\x08').exact_view()).exact_view(),
  )
  assert_eq(ok.sig_params[0].length(), 64)
  // EdDsaLegacy (22) is forbidden for version 6.
  try
    @packet.SignaturePacket::parse(
      v6_signature_body(22, Bytes::new(0).exact_view()).exact_view(),
    )
  catch {
    @error.Malformed(msg~) => assert_true(msg.contains("EdDsaLegacy"))
    _ => fail("expected a PgpError for EdDsaLegacy in a v6 signature")
  } noraise {
    _ => fail("a v6 signature with EdDsaLegacy was accepted")
  }
  // Ed25519 with 63 or 65 octets is malformed.
  for n in [63, 65] {
    try
      @packet.SignaturePacket::parse(
        v6_signature_body(27, Bytes::make(n, b'\x08').exact_view()).exact_view(),
      )
    catch {
      @error.Malformed(msg~) => assert_true(msg.contains("64 octets"))
      _ => fail("expected a PgpError for the Ed25519 length")
    } noraise {
      _ => fail("a v6 Ed25519 signature of \{n} octets was accepted")
    }
  }
}
