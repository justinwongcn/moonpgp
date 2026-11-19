///|
/// X2 regression probes (audit-conformance-20261119): §4.3 criticality gate
/// (c1g1) and issuer-fingerprint version cross (c1g4). Each probe is a
/// three-way attack on a freshly landed conformance fix.

///|
fn x2_parse_one(raw : Array[Byte]) -> Array[RawPacket] raise {
  parse_packets(Bytes::from_array(raw).exact_view())
}

///|
fn x2_raises(f : () -> Unit raise) -> Bool {
  try {
    f()
    false
  } catch {
    _ => true
  }
}

///|
/// A1a: tag 21 (Padding) is exempt from the criticality gate and a stream
/// carrying it parses — a legit stream must not be rejected (false-positive
/// surface of the c1g1 gate).
test "x2 A1a: Padding tag 21 passes the criticality gate" {
  // New-format header for tag 21: 0xC0 | 21 = 0xD5, one-octet length.
  let ps = x2_parse_one([0xD5, 0x02, 0xAB, 0xCD, 0xC0 | 11, 0x03, 1, 2, 3])
  assert_eq(ps.length(), 2)
  assert_true(ps[0].tag() is Unknown(21))
  assert_true(ps[1].tag() is Literal)
}

///|
/// A1b: tag 0-15/39 unknown critical tags must reject. 39 is the highest
/// critical ID; 0 is reserved; 15 and 16 are unassigned.
test "x2 A1b: unknown critical tags 0/15/16/39 reject" {
  // New format: 0xC0 | tag.
  assert_true(x2_raises(() => ignore(x2_parse_one([0xC0 | 0, 0x00]))))
  assert_true(x2_raises(() => ignore(x2_parse_one([0xC0 | 15, 0x00]))))
  assert_true(x2_raises(() => ignore(x2_parse_one([0xC0 | 16, 0x00]))))
  assert_true(x2_raises(() => ignore(x2_parse_one([0xC0 | 39, 0x00]))))
  // Old format tag field is 4 bits: tag 15 = 0x80 | (15 << 2) | 0 = 0xBC.
  assert_true(x2_raises(() => ignore(x2_parse_one([0xBC, 0x00]))))
}

///|
/// A1c: tags 40-63 are non-critical — unknown ones MUST be ignored, and
/// 40/63 are the boundary IDs. The gate must not reject them (过严).
test "x2 A1c: unknown non-critical tags 40/63 parse" {
  let ps40 = x2_parse_one([0xC0 | 40, 0x01, 0xAA, 0xC0 | 11, 0x03, 1, 2, 3])
  assert_eq(ps40.length(), 2)
  assert_true(ps40[0].tag() is Unknown(40))
  let ps63 = x2_parse_one([0xC0 | 63, 0x01, 0xAA])
  assert_eq(ps63.length(), 1)
  assert_true(ps63[0].tag() is Unknown(63))
}

///|
/// A1d: the gate fires before length parsing, so a truncated unknown
/// critical packet reports the tag, and a truncated non-critical one
/// still fails on the length — no path lets garbage through.
test "x2 A1d: truncated unknown packets still fail closed" {
  assert_true(x2_raises(() => ignore(x2_parse_one([0xC0 | 41]))))
  assert_true(x2_raises(() => ignore(x2_parse_one([0xC0 | 5, 0x10, 1, 2]))))
}

///|
/// A2a: the c1g4 version cross must hold on BOTH subpacket areas. A v4
/// signature with a v6 issuer fingerprint (33-octet body, version octet 6)
/// in the unhashed area is malformed.
test "x2 A2a: v4 sig rejects v6 fp in unhashed area" {
  let fp_v6 : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_FINGERPRINT,
    body: Bytes::from_array([6]).add(Bytes::make(32, 0x22)),
  }
  assert_true(x2_raises(() => validate_issuer_subpackets([fp_v6], 4)))
  assert_true(x2_raises(() => validate_hashed_subpackets([fp_v6], 4)))
  // And the v6-length body with a v4 octet in the unhashed area too.
  let fp_v4_wide : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_FINGERPRINT,
    body: Bytes::from_array([6]).add(Bytes::make(32, 0x22)),
  }
  assert_true(x2_raises(() => validate_issuer_subpackets([fp_v4_wide], 4)))
}

///|
/// A2b (lax-1 regression): a v6 signature with a v4-shaped issuer
/// fingerprint (21-octet body, version octet 6) — the octet matches but
/// the length is the v4 shape. The (version, length) joint lock rejects
/// it in BOTH validators, together with the mirror case (v4 octet in a
/// 33-octet body).
test "x2 A2b: a (version, length) mismatch in the issuer fp is malformed" {
  let fp_short : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_FINGERPRINT,
    body: Bytes::from_array([6]).add(Bytes::make(20, 0x22)),
  }
  assert_true(x2_raises(() => validate_issuer_subpackets([fp_short], 6)))
  assert_true(x2_raises(() => validate_hashed_subpackets([fp_short], 6)))
  // Mirror: v4 sig with a 33-octet body whose octet says 4.
  let fp_wide : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_FINGERPRINT,
    body: Bytes::from_array([4]).add(Bytes::make(32, 0x22)),
  }
  assert_true(x2_raises(() => validate_issuer_subpackets([fp_wide], 4)))
  assert_true(x2_raises(() => validate_hashed_subpackets([fp_wide], 4)))
}

///|
/// A2c (wire level, lax-1 regression): a v6 signature carrying a
/// 21-octet fp (octet 6) in the unhashed area is malformed — the
/// (version, length) joint lock applies to the unhashed area too, so
/// the v4-shaped fingerprint no longer parses end to end.
test "x2 A2c: v6 sig + 21-octet unhashed fp is malformed" {
  // v6 signature: hashed area empty, unhashed area carries the 21-octet
  // fp with version octet 6 (the v4 length shape), Ed25519 material.
  let fp : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_FINGERPRINT,
    body: Bytes::from_array([6]).add(Bytes::make(20, 0x33)),
  }
  let raw : SignaturePacket = {
    version: 6,
    sig_type: BinaryDocument,
    pub_algo: Ed25519,
    hash_algo: 8,
    hashed_subpackets: [],
    unhashed_subpackets: [fp],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0x1F2F,
    salt: Bytes::make(16, 0x00),
    sig_params: [Bytes::make(64, 0x11)],
  }
  let wire = raw.to_body()
  let raised = try {
    ignore(SignaturePacket::parse(wire.exact_view()))
    false
  } catch {
    @error.Malformed(msg~) => {
      assert_true(msg.contains("issuer fingerprint length"))
      true
    }
    _ => fail("expected a Malformed for the (version, length) mismatch")
  }
  assert_true(raised)
}

///|
/// A2d: the headline c1g4 case at wire level — v4 signature with a v6
/// issuer fingerprint in the hashed area must fail parse.
test "x2 A2d: v4 sig with v6 fp in hashed area fails parse" {
  // v4 body: version 4, type 0x00, Ed25519 (27), SHA-256, hashed area
  // carries the 33-octet fp with version octet 6.
  let fp = Bytes::from_array([6]).add(Bytes::make(32, 0x33))
  let hashed_len = 1 + 1 + 33
  let body : Array[Byte] = [
    4,
    0x00,
    27,
    8,
    (hashed_len >> 8).to_byte(),
    (hashed_len & 0xFF).to_byte(),
    21,
    33,
    6,
  ]
  let b = Bytes::from_array(body)
    .add(fp)
    .add(Bytes::from_array([0, 0, 0x1F, 0x2F]))
    .add(Bytes::make(64, 0x11))
  assert_true(x2_raises(() => ignore(SignaturePacket::parse(b.exact_view()))))
}
