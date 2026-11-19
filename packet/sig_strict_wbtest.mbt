///|
/// Whitebox tests for the audit-B3 parser-strictness gates: each one used
/// to accept a shape the RFC leaves undefined (or a sibling branch
/// rejected), letting wire meaning drift between the two levels.

///|
test "subpacket length first octets 224-254 are refused (F4)" {
  // First octet 230 is the packet-level partial-length range: undefined
  // for subpackets, previously decoded as a two-octet length.
  let raised = try {
    ignore(
      parse_subpackets(
        Bytes::from_array([230, 0x05, 1, 2, 3, 4, 5]).exact_view(),
      ),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // The three legal shapes still parse (control).
  let ok = parse_subpackets(
    Bytes::from_array([0x05, 1, 2, 3, 4, 5, 0xff, 0, 0, 0, 2, 1, 2]).exact_view(),
  )
  assert_eq(ok.length(), 2)
}

///|
test "issuer subpacket bodies must match the RFC shapes (F5)" {
  let short_id : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_KEY_ID,
    body: Bytes::make(7, 0x11),
  }
  let raised = try {
    validate_hashed_subpackets([short_id], 4)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  let ok_id : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_KEY_ID,
    body: Bytes::make(8, 0x11),
  }
  validate_hashed_subpackets([ok_id], 4)
  let bad_fp : SigSubpacket = {
    critical: false,
    sub_type: SIGSUB_ISSUER_FINGERPRINT,
    body: Bytes::make(20, 0x22),
  }
  let raised_fp = try {
    validate_hashed_subpackets([bad_fp], 4)
    false
  } catch {
    _ => true
  }
  assert_true(raised_fp)
  // v4 signature: the issuer fingerprint body starts with key version 4.
  validate_hashed_subpackets(
    [
      {
        critical: false,
        sub_type: SIGSUB_ISSUER_FINGERPRINT,
        body: Bytes::from_array([4]).add(Bytes::make(20, 0x22)),
      },
    ],
    4,
  )
  // v6 signature: version 6 octet + 32-octet fingerprint.
  validate_hashed_subpackets(
    [
      {
        critical: false,
        sub_type: SIGSUB_ISSUER_FINGERPRINT,
        body: Bytes::from_array([6]).add(Bytes::make(32, 0x22)),
      },
    ],
    6,
  )
  // A version octet that disagrees with the signature version is
  // malformed (RFC 9580 §5.2.3.35, audit c1g4).
  let raised_version = try {
    validate_hashed_subpackets(
      [
        {
          critical: false,
          sub_type: SIGSUB_ISSUER_FINGERPRINT,
          body: Bytes::from_array([6]).add(Bytes::make(20, 0x22)),
        },
      ],
      4,
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised_version)
}

///|
test "RSA signature MPI consumes exactly (F6)" {
  let base : Array[Byte] = [
    0x04, 0x00, 0x01, // RSA
     0x08, // SHA-256
     0, 0, // hashed area empty
     0, 0, // unhashed area empty
     0x1F, 0x2F, // fast hash
     0x00, 0x08, 0x81, // MPI: 8 bits, value 0x81
  ]
  let trailer : Array[Byte] = [0xff]
  // Trailing octet after the MPI: a framing violation on the RSA branch
  // that the exact-consuming Ed25519 branch never had.
  let raised = try {
    ignore(
      SignaturePacket::parse(Bytes::from_array(base + trailer).exact_view()),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Without the trailer the same signature parses (control).
  ignore(SignaturePacket::parse(Bytes::from_array(base).exact_view()))
}

///|
test "RSA PKESK MPI consumes exactly (F6)" {
  let base : Array[Byte] = [0x03] +
    Array::make(8, b'\x11') +
    ([0x01, 0x00, 0x08, 0x81] : Array[Byte])
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
test "unknown tags refuse serialization instead of wrapping (F8)" {
  let raised = try {
    ignore(serialize_packet(Unknown(70), Bytes::make(0, b'\x00').exact_view()))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // A known tag serializes fine (control).
  ignore(serialize_packet(Literal, Bytes::make(0, b'\x00').exact_view()))
}

///|
test "a short-parameter legacy key body reports malformed, not abort (F9)" {
  let pkt : PublicKeyPacket = {
    version: 4,
    creation_time: 0,
    algo: Ecdh,
    params: [],
  }
  let raised = try {
    ignore(pkt.to_body())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // The secret side serializes the public body first, so the same guard
  // covers the secret path.
  let secret : SecretKeyPacket = {
    public: pkt,
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::make(0, b'\x00'),
    iv: Bytes::make(0, b'\x00'),
    secret_material: Bytes::make(0, b'\x00'),
    dummy: false,
  }
  let raised_secret = try {
    ignore(secret.to_body())
    false
  } catch {
    _ => true
  }
  assert_true(raised_secret)
}
