///|
test "packet header roundtrip across length classes" {
  let tags : Array[@packet.PacketTag] = [
    @packet.Pkesk,
    @packet.Signature,
    @packet.Literal,
    @packet.Seipd,
  ]
  for tag in tags {
    for size in [0, 100, 191, 192, 500, 8383, 8384, 20000] {
      let body = Bytes::make(size, b'\x5A')
      let wire = @packet.serialize_packet(tag, body.exact_view())
      let parsed = @packet.parse_packets(wire.exact_view())
      assert_eq(parsed.length(), 1)
      assert_eq(parsed[0].tag(), tag)
      assert_eq(parsed[0].body(), body)
    }
  }
}

///|
test "old-format header roundtrip" {
  let body = Bytes::make(300, b'\x01')
  let wire = @packet.serialize_packet_old(@packet.PublicKey, body.exact_view())
  let parsed = @packet.parse_packets(wire.exact_view())
  assert_eq(parsed.length(), 1)
  assert_eq(parsed[0].tag(), @packet.PublicKey)
  assert_eq(parsed[0].body(), body)
}

///|
test "partial body lengths are accumulated" {
  // Header: new format tag 11 (literal), partial chunk of 2^9=512, then
  // final chunk of 10 octets.
  let w = @packet.Writer::new()
  w.u8(0xCB)
  w.u8(0xE9)
  for _ in 0..<512 {
    w.u8(0xAA)
  }
  w.u8(10)
  for _ in 0..<10 {
    w.u8(0xBB)
  }
  let parsed = @packet.parse_packets(w.to_bytes().exact_view())
  assert_eq(parsed.length(), 1)
  assert_eq(parsed[0].tag(), @packet.Literal)
  assert_eq(parsed[0].body().length(), 512 + 10)
}

///|
test "mpi encoding" {
  let w = @packet.Writer::new()
  w.mpi(Bytes::from_array([0x01]))
  w.mpi(Bytes::from_array([]))
  w.mpi(Bytes::from_array([0x80, 0x00]))
  w.mpi(Bytes::from_array([0x00, 0x01]))
  let out = w.to_bytes()
  // 0x0001 01 | 0x0000 | 0x0010 8000 | 0x0001 01
  assert_eq(out, Bytes::from_array([0, 1, 1, 0, 0, 0, 16, 128, 0, 0, 1, 1]))
}

///|
test "RFC 9580 A.1 sample public key packet decodes as one packet" {
  let wire = @primitives.from_hex(
    "98330453f35f0b1609" +
    "2b06010401da470f010107403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406",
  )
  let parsed = @packet.parse_packets(wire.exact_view())
  assert_eq(parsed.length(), 1)
  assert_eq(parsed[0].tag(), @packet.PublicKey)
  assert_eq(parsed[0].body().length(), 0x33)
}

///|
test "RFC 9580 A.2 sample signature packet parses" {
  let wire = @primitives.from_hex(
    "885e040016080006050255f95f9500" +
    "0a0910" +
    "8cfde12197965a9a" +
    "f622" +
    "00ff56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed3366" +
    "0100d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404",
  )
  let parsed = @packet.parse_packets(wire.exact_view())
  assert_eq(parsed.length(), 1)
  assert_eq(parsed[0].tag(), @packet.Signature)
  let sig = @packet.SignaturePacket::parse(parsed[0].body().exact_view())
  assert_eq(@packet.SignaturePacket::sig_type(sig), @packet.BinaryDocument)
  assert_eq(@packet.SignaturePacket::pub_algo(sig), @packet.EdDsaLegacy)
  assert_eq(@packet.SignaturePacket::hash_algo(sig), 8)
  assert_eq(@packet.SignaturePacket::fast_hash(sig), 0xf622)
  // Creation time subpacket 0x55f95f95 = 2015-09-16 12:24:53 UTC.
  assert_eq(@packet.SignaturePacket::creation_time(sig), Some(0x55f95f95))
  // Issuer key id from the unhashed area.
  assert_eq(
    @packet.SignaturePacket::issuer_key_id(sig),
    Some(@primitives.from_hex("8cfde12197965a9a")),
  )
}

///|
test "signature packet roundtrip (RSA-shaped)" {
  let creation = Bytes::from_array([0x55, 0xf9, 0x5f, 0x95])
  let hashed : Array[@packet.SigSubpacket] = [
    { critical: false, sub_type: @packet.SIGSUB_CREATION_TIME, body: creation, },
  ]
  let unhashed : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
      body: @primitives.from_hex("8cfde12197965a9a"),
    },
  ]
  let sig : @packet.SignaturePacket = {
    sig_type: @packet.CanonicalTextDocument,
    pub_algo: @packet.RsaEncryptOrSign,
    hash_algo: 8,
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0x1234,
    sig_params: [@primitives.from_hex("deadbeefcafe")],
  }
  let body = sig.to_body()
  let again = @packet.SignaturePacket::parse(body.exact_view())
  assert_eq(again.sig_type(), @packet.CanonicalTextDocument)
  assert_eq(again.pub_algo(), @packet.RsaEncryptOrSign)
  assert_eq(again.hash_algo(), 8)
  assert_eq(again.fast_hash(), 0x1234)
  assert_eq(again.creation_time(), Some(0x55f95f95))
  assert_eq(
    again.issuer_key_id(),
    Some(@primitives.from_hex("8cfde12197965a9a")),
  )
}

///|
test "pkesk and skesk roundtrip" {
  let pkesk : @packet.PkeskPacket = {
    key_id: @primitives.from_hex("0123456789abcdef"),
    pub_algo: @packet.RsaEncryptOrSign,
    encrypted: @primitives.from_hex("feedface01"),
    ecdh_ephemeral: Bytes::new(0),
  }
  let body = pkesk.to_body()
  let parsed = @packet.PkeskPacket::parse(body.exact_view())
  assert_eq(parsed.key_id(), @primitives.from_hex("0123456789abcdef"))
  assert_eq(parsed.pub_algo(), @packet.RsaEncryptOrSign)
  assert_eq(parsed.encrypted(), @primitives.from_hex("feedface01"))

  let skesk : @packet.SkeskPacket = {
    cipher_algo: 9,
    s2k: @s2k.Salted(
      @primitives.Sha256,
      Bytes::from_array([1, 2, 3, 4, 5, 6, 7, 8]),
    ),
    encrypted_session_key: Bytes::new(0),
  }
  let parsed2 = @packet.SkeskPacket::parse(skesk.to_body().exact_view())
  assert_eq(parsed2.cipher_algo(), 9)
  assert_eq(parsed2.s2k(), skesk.s2k())
  assert_eq(parsed2.encrypted_session_key().length(), 0)
}

///|
test "literal packet roundtrip with utf8 file name" {
  let lit = @packet.LiteralPacket::binary(
    @primitives.utf8_bytes("héllo wörld\n"),
    file_name="note.txt",
  )
  let parsed = @packet.LiteralPacket::parse(lit.to_body().exact_view())
  assert_eq(parsed.file_name(), "note.txt")
  assert_eq(parsed.data(), @primitives.utf8_bytes("héllo wörld\n"))
  assert_eq(parsed.format(), 'b')
}

///|
test "seipd packet roundtrip" {
  let seipd : @packet.SeipdPacket = {
    version: 1,
    ciphertext: Bytes::make(37, b'\x03'),
  }
  let parsed = @packet.SeipdPacket::parse(seipd.to_body().exact_view())
  assert_eq(parsed.version, 1)
  assert_eq(parsed.ciphertext, Bytes::make(37, b'\x03'))
}

///|
test "session key checksum" {
  // Sum of 0x01..0x04 = 0x0A.
  assert_eq(@packet.session_key_checksum(Bytes::from_array([1, 2, 3, 4])), 0x0A)
}

///|
test "reader truncation raises" {
  let r = @packet.Reader::new(Bytes::from_array([1, 2]).exact_view())
  ignore(r.read_u16())
  let raised = try {
    let _ = r.read_u8()
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
