///|
test "ecdh kdf sym algo guards malformed key params" {
  // The packet layer accepts ECDH keys whose KDF field is shorter than 4
  // octets; ecdh_kdf_sym_algo used to index kdf_field[3] unguarded and
  // panic. It must raise instead.
  let bad : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: 0,
    algo: @packet.Ecdh,
    params: [
      Bytes::new(0),
      Bytes::new(0),
      Bytes::from_array([b'\x03', b'\x01', b'\x02']),
    ],
  }
  let raised = try {
    let _ = ecdh_kdf_sym_algo(bad)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Fewer than three params is rejected the same way.
  let short : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: 0,
    algo: @packet.Ecdh,
    params: [Bytes::new(0), Bytes::new(0)],
  }
  let raised2 = try {
    let _ = ecdh_kdf_sym_algo(short)
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
  // Well-formed params still read the algo id from octet 3 (AES-256 = 9).
  let ok : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: 0,
    algo: @packet.Ecdh,
    params: [
      Bytes::new(0),
      Bytes::new(0),
      Bytes::from_array([b'\x03', b'\x01', b'\x02', b'\x09']),
    ],
  }
  assert_eq(ecdh_kdf_sym_algo(ok), 9)
}
