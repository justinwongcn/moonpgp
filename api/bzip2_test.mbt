///|
/// BZip2 (compression algorithm 3) is decode-only by design: the pure
/// MoonBit codec in the compress package reads what gpg emits with
/// `--compress-algo bzip2`, while this library keeps producing ZIP/ZLIB
/// (so the error for an output request says exactly that).

///|
test "BZip2 output compression is rejected with an explicit error" {
  let data = @primitives.utf8_bytes("bzip2 is decode-only")
  let encrypt = @api.pgp()
    .encryption()
    .password("pw")
    .compress(@compress.BZip2)
    .finish()
  let raised = try {
    let _ = encrypt(data)
    false
  } catch {
    e => {
      // The error names the algorithm id and states the decode-only scope.
      let msg = e.to_string()
      assert_true(msg.contains("3"))
      assert_true(msg.contains("BZip2 is decode-only"))
      true
    }
  }
  assert_true(raised)
}

///|
test "an OpenPGP message compressed with BZip2 is readable" {
  let key = @api.generate_ed25519_key("BZ <bz@example.com>")
  // `bzip2 -9` over a one-packet inner stream (new-format literal packet
  // header 0xCB + length, then format 'b', empty name, date 0, and the
  // payload "hi, bzip2"): a real bzip2 stream (block magic, Huffman
  // tables, MTF/RLE2, block + stream CRCs) so the packet walk exercises
  // the full decode path, not just the algo gate.
  let bzip2_stream = @primitives.from_hex(
    "425a6839314159265359f718572800000859846000c00410001060401000082000310340d0221a6d34c83b10c62b25309e8bb9229c28487b8c2b9400",
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.Compressed,
      Bytes::from_array([3]).add(bzip2_stream).exact_view(),
    ).exact_view(),
  )
  let message = @armor.encode(w.to_bytes().exact_view())
  let (data, status) = @api.verify_inline(message, key.to_public())
  assert_eq(data, @primitives.utf8_bytes("hi, bzip2"))
  assert_eq(status, @api.VerifyStatus::NotSigned)
}

///|
test "corrupt BZip2 payload inside a message fails loudly" {
  let key = @api.generate_ed25519_key("BZ <bz@example.com>")
  // An algo-3 packet whose payload is not a bzip2 stream at all.
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.Compressed,
      Bytes::from_array([3])
      .add(@primitives.utf8_bytes("not bzip2"))
      .exact_view(),
    ).exact_view(),
  )
  let message = @armor.encode(w.to_bytes().exact_view())
  let raised = try {
    let _ = @api.verify_inline(message, key.to_public())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("bzip2"))
      true
    }
  }
  assert_true(raised)
}
