///|
/// BZip2 (compression algorithm 3) is unsupported in BOTH directions; the
/// messages must say so explicitly instead of the old misleading
/// "decode-only" wording (consolidation fix).

///|
test "BZip2 output compression is rejected with an explicit error" {
  let data = @primitives.utf8_bytes("bzip2 is not implemented")
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
      // The error names the algorithm id and states BZip2 is not implemented.
      let msg = e.to_string()
      assert_true(msg.contains("3"))
      assert_true(msg.contains("BZip2 is not implemented"))
      true
    }
  }
  assert_true(raised)
}

///|
test "a BZip2-compressed packet fails to decompress with an explicit error" {
  let key = @api.generate_ed25519_key("BZ <bz@example.com>")
  // An algo-3 Compressed packet around arbitrary bytes: the packet walk
  // rejects the algorithm octet before ever touching the payload, so no
  // real inner packet stream is needed.
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.Compressed,
      Bytes::from_array([3])
      .add(@primitives.utf8_bytes("not real bzip2 data"))
      .exact_view(),
    ).exact_view(),
  )
  let message = @armor.encode(w.to_bytes().exact_view())
  let raised = try {
    let _ = @api.verify_inline(message, key.to_public())
    false
  } catch {
    e => {
      let msg = e.to_string()
      assert_true(msg.contains("BZip2 is not implemented"))
      true
    }
  }
  assert_true(raised)
}
