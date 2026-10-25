///|
/// S-series fix regression tests that only need the public surface.

///|
/// One algo-0 (uncompressed) Compressed packet around `inner`.
fn wrap_uncompressed(inner : Bytes) -> Bytes {
  @packet.serialize_packet(
    @packet.Compressed,
    Bytes::from_array([0]).add(inner).exact_view(),
  )
}

///|
test "S03: deeply nested uncompressed packets are rejected" {
  let key = @api.generate_key("S3 <s3@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("nested payload")
  let literal = @packet.serialize_packet(
    @packet.Literal,
    @packet.LiteralPacket::binary(data, file_name="m.txt")
    .to_body()
    .exact_view(),
  )
  // Two layers still walk to the literal (no signature attached).
  let shallow = wrap_uncompressed(wrap_uncompressed(literal))
  let (out, status) = @api.verify_inline(
    @armor.Message.encode(shallow.exact_view()),
    key.to_public(),
  )
  assert_eq(out, data)
  assert_eq(status, @api.NotSigned)
  // Five layers are refused before the recursion can grow unbounded.
  let mut deep = literal
  for _ in 0..<5 {
    deep = wrap_uncompressed(deep)
  }
  let raised = try {
    let _ = @api.verify_inline(
      @armor.Message.encode(deep.exact_view()),
      key.to_public(),
    )
    false
  } catch {
    e => {
      // The depth guard fired, not some unrelated parse error.
      assert_true("\{e}".contains("nested"))
      true
    }
  }
  assert_true(raised)
}

///|
test "S03: nested decompression draws from one cumulative budget" {
  let key = @api.generate_key("S3b <s3b@example.com>", bits=2048)
  // 2000 octets of highly compressible literal data.
  let data = Bytes::make(2000, b'A')
  let literal = @packet.serialize_packet(
    @packet.Literal,
    @packet.LiteralPacket::binary(data, file_name="m.txt")
    .to_body()
    .exact_view(),
  )
  // Two ZIP layers: the outer one expands to a ~40-octet compressed
  // stream, the inner one to the full ~2006-octet literal wire.
  let comp1 = @packet.serialize_packet(
    @packet.Compressed,
    Bytes::from_array([1])
    .add(@compress.zip_compress(literal.exact_view()))
    .exact_view(),
  )
  let comp2 = @packet.serialize_packet(
    @packet.Compressed,
    Bytes::from_array([1])
    .add(@compress.zip_compress(comp1.exact_view()))
    .exact_view(),
  )
  let msg = @armor.Message.encode(comp2.exact_view())
  // A 1000-octet TOTAL budget: the outer expansion costs ~40, and the
  // inner ~2006 cannot fit in what remains — the walk fails even though
  // each layer alone would fit the per-call cap.
  let raised = try {
    let _ = @api.verify_inline(msg, key.to_public(), max_decompressed=1000)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // A generous shared budget lets both expansions through.
  let (out, status) = @api.verify_inline(
    msg,
    key.to_public(),
    max_decompressed=5000,
  )
  assert_eq(out, data)
  assert_eq(status, @api.NotSigned)
}

///|
test "S04: a tampered RSA PKESK fails uniformly inside the SEIPD check" {
  let recipient = @api.generate_key("S4 <s4@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("secret payload")
  let msg = @api.encrypt_to_recipients(data.exact_view(), [
    recipient.to_public(),
  ])
  let bytes = @armor.ArmorBlock::data(@armor.decode(msg))
  // Corrupt one octet inside the first PKESK's RSA ciphertext (well past
  // the version / key id / algorithm header).
  let tampered = Bytes::makei(bytes.length(), i => {
    if i == 20 {
      (bytes[20].to_int() ^ 0x5A).to_byte()
    } else {
      bytes[i]
    }
  })
  let err = try {
    let _ = @api.decrypt_with_private_key(
      @armor.Message.encode(tampered.exact_view()),
      recipient,
    )
    ""
  } catch {
    e => "\{e}"
  }
  // The failure must surface as a SEIPD integrity error — never as an
  // RSA padding / payload / checksum error (a Bleichenbacher oracle).
  assert_true(err.contains("seipd:"))
  assert_false(err.contains("rsa:"))
  assert_false(err.contains("checksum mismatch"))
}

///|
test "S13: a hidden-recipient PKESK (all-zero key id) still decrypts" {
  let recipient = @api.generate_key("S13 <s13@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("hidden recipient payload")
  let msg = @api.encrypt_to_recipients(data.exact_view(), [
    recipient.to_public(),
  ])
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(@armor.decode(msg)).exact_view(),
  )
  let w = @packet.Writer::new()
  for p in packets {
    if p.tag() == @packet.Pkesk {
      // Zero out the recipient key id: the v3 PKESK now matches no key
      // by id and must be tried against every candidate instead.
      let pkesk = @packet.PkeskPacket::parse(p.body().exact_view())
      let anon = { ..pkesk, key_id: Bytes::make(8, b'\x00'), }
      w.bytes(
        @packet.serialize_packet(@packet.Pkesk, anon.to_body().exact_view()).exact_view(),
      )
    } else {
      w.bytes(
        @packet.serialize_packet(p.tag(), p.body().exact_view()).exact_view(),
      )
    }
  }
  let hidden = @armor.Message.encode(w.to_bytes().exact_view())
  assert_eq(@api.decrypt_with_private_key(hidden, recipient), data)
  // The session-key recovery flow accepts hidden recipients too.
  let ok = try {
    let _ = @api.recover_session_key_with_key(hidden, recipient)
    true
  } catch {
    _ => false
  }
  assert_true(ok)
}

///|
test "S14: created is honored by the inline and cleartext entries" {
  let key = @api.generate_key("S14 <s14@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("reproducible")
  let fixed : Int32 = 1_234_567_890
  // Inline: the trailing signature packet carries the fixed time.
  let inline = @api.sign_inline(data.exact_view(), key, created=fixed)
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(@armor.decode(inline)).exact_view(),
  )
  let mut creation : Int32? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      creation = @packet.SignaturePacket::parse(p.body().exact_view()).creation_time()
    }
  }
  assert_eq(creation, Some(fixed))
  // Cleartext: the signature armor inside the cleartext message.
  let clear = @api.sign_cleartext("reproducible text", key, created=fixed)
  let sig_block = @armor.decode(clear)
  let sig_packets = @packet.parse_packets(
    @armor.ArmorBlock::data(sig_block).exact_view(),
  )
  let mut clear_creation : Int32? = None
  for p in sig_packets {
    if p.tag() == @packet.Signature {
      clear_creation = @packet.SignaturePacket::parse(p.body().exact_view()).creation_time()
    }
  }
  assert_eq(clear_creation, Some(fixed))
}
