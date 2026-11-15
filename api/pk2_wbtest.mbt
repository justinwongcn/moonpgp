///|
/// Audit pk2: the decrypted packet stream must survive Unknown
/// (reserved-number) tags the way parse accepts them — gpg skips such
/// packets. The old extract_literal re-serialized everything after a
/// one-pass signature, and the F8 write-side guard refused Unknown tags,
/// turning a legally-formed message into a hard decrypt failure.

///|
fn pk2_inner_stream() -> Bytes raise {
  // minimal v4 one-pass signature body: version|sigtype|hash|pubkey|last
  let ops = Bytes::from_array([4, 0, 8, 1, 1])
  let literal_body = @packet.LiteralPacket::binary(b"payload").to_body()
  let literal = @packet.serialize_packet(
    @packet.Literal,
    literal_body.exact_view(),
  )
  // hand-built new-format packet with reserved tag 21 (0xC0 | 21 = 0xD5)
  let unknown = Bytes::from_array([0xD5, 8]).add(b"reserved")
  @packet.serialize_packet(@packet.OnePassSig, ops.exact_view())
  .add(literal)
  .add(unknown)
}

///|
test "extract_literal delivers the literal past unknown tags (pk2)" {
  let data = extract_literal(pk2_inner_stream().exact_view(), 1_000_000)
  assert_eq(data, b"payload")
}

///|
test "extract_literal skips a leading unknown-tag packet (pk2)" {
  let unknown = Bytes::from_array([0xD5, 8]).add(b"reserved")
  let stream = unknown.add(pk2_inner_stream())
  let data = extract_literal(stream.exact_view(), 1_000_000)
  assert_eq(data, b"payload")
}
