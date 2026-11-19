// Hacker-round probes (2026-11-13), packet facet: read-side parity gaps
// the B3 batch claimed but did not deliver. Each test asserts the DESIRED
// behavior; a red run confirms the defect.

///|
/// The F6 guard landed on the RSA branch with a comment claiming parity
/// with "the exact-consuming X25519/ECDH branches" — which consume
/// nothing of the sort: trailing octets after the wrapped key are
/// silently dropped and would vanish again on re-serialization.
test "X25519 PKESK consumes exactly (F6 residual)" {
  let base : Array[Byte] = [0x03] +
    Array::make(8, b'\x11') +
    ([0x19] : Array[Byte]) +
    Array::make(32, b'\x42') +
    ([0x01, 0xAA] : Array[Byte])
  let trailer : Array[Byte] = [0xff]
  let raised = try {
    ignore(PkeskPacket::parse(Bytes::from_array(base + trailer).exact_view()))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  ignore(PkeskPacket::parse(Bytes::from_array(base).exact_view()))
}

///|
test "ECDH PKESK consumes exactly (F6 residual)" {
  // eph = MPI of 8 bits carrying one octet.
  let base : Array[Byte] = [0x03] +
    Array::make(8, b'\x11') +
    ([0x12, 0x00, 0x08, 0x41, 0x01, 0xAA] : Array[Byte])
  let trailer : Array[Byte] = [0xff]
  let raised = try {
    ignore(PkeskPacket::parse(Bytes::from_array(base + trailer).exact_view()))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  ignore(PkeskPacket::parse(Bytes::from_array(base).exact_view()))
}

///|
/// F5 gated Issuer lengths on the hashed area only; the unhashed area —
/// where gpg actually puts Issuer Key ID — parses a 7-octet issuer and
/// hands it back from issuer_key_id() unguarded.
test "unhashed Issuer Key ID enforces the exact 8-octet shape (F5 residual)" {
  // Control: the same body with an EMPTY unhashed area parses today, so
  // any raise below is attributable to the short issuer, not the shape.
  let no_unhashed : Array[Byte] = [
      0x04, 0x00, 0x1B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ] +
    Array::make(64, b'\x33')
  ignore(SignaturePacket::parse(Bytes::from_array(no_unhashed).exact_view()))
  // v4 sig: ver/type/pub/hash, hashed_len=0, unhashed_len=9,
  // subpacket [len=8, type=16, 7×0x11], fast_hash=0, Ed25519 params.
  let body : Array[Byte] = [0x04, 0x00, 0x1B, 0x08, 0x00, 0x00, 0x00, 0x09] +
    ([0x08, 0x10] : Array[Byte]) +
    Array::make(7, b'\x11') +
    ([0x00, 0x00] : Array[Byte]) +
    Array::make(64, b'\x33')
  // Desired: the unhashed area gets the same exact-length gate as the
  // hashed area (F5's stated scope); today the short issuer parses and
  // issuer_key_id() hands the 7-octet body straight back to callers.
  let raised = try {
    ignore(SignaturePacket::parse(Bytes::from_array(body).exact_view()))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
/// F8 closed the new-format Unknown-tag hole; serialize_packet_old still
/// wraps tag 70 into first octet 0x98 — a legal old-format header for
/// tag 6 (PublicKey) — silently mislabeling the packet.
test "old-format serialization refuses unknown tags (F8 residual)" {
  let raised = try {
    ignore(
      serialize_packet_old(Unknown(70), Bytes::make(0, b'\x00').exact_view()),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // A known tag still serializes (control).
  ignore(serialize_packet_old(Literal, b"payload"))
}

///|
/// Cleanup round (j15, user-approved): to_body replayed parse's v6
/// rejections only partially — S2K usage 255 and legacy cipher-id usage
/// octets still serialized on a v6 packet although parse rejects both,
/// so a direct construction could round-trip a shape this library
/// refuses to read.
test "v6 secret key bodies refuse usage 255 and legacy usage (j15)" {
  let pub6 : PublicKeyPacket = {
    version: 6,
    creation_time: 0,
    algo: Ed25519,
    params: [Bytes::make(32, 0x42)],
  }
  let base : SecretKeyPacket = {
    public: pub6,
    s2k_usage: 255,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::make(0, b'\x00'),
    iv: Bytes::make(0, b'\x00'),
    secret_material: b"seed",
    dummy: false,
  }
  let raised255 = try {
    ignore(base.to_body())
    false
  } catch {
    _ => true
  }
  assert_true(raised255)
  let legacy : SecretKeyPacket = { ..base, s2k_usage: 1, cipher_algo: 7, }
  let raised_legacy = try {
    ignore(legacy.to_body())
    false
  } catch {
    _ => true
  }
  assert_true(raised_legacy)
  // Controls: the shapes parse accepts still serialize.
  let plain : SecretKeyPacket = { ..base, s2k_usage: 0, }
  ignore(plain.to_body())
  let u254 : SecretKeyPacket = {
    ..base,
    s2k_usage: 254,
    cipher_algo: 9,
    s2k_spec: Bytes::make(2, 0),
  }
  ignore(u254.to_body())
}
