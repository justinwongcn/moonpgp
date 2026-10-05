///|
test "zero-length signature subpacket is rejected, not a panic" {
  // Subpacket length octet 0x00 => zero-length body: this must raise
  // PgpError. It used to index body[0] on the empty Bytes and panic,
  // reachable from untrusted signatures via verify paths.
  let raised = try {
    let _ = parse_subpackets(Bytes::from_array([b'\x00']).exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "signature subpackets still parse across length classes" {
  // Sanity: the zero-length guard must not disturb well-formed subpackets
  // (1-octet and 255-prefixed u32 length forms). Body includes the type
  // octet on the wire; the stored body strips it.
  let subs = parse_subpackets(
    Bytes::from_array([
      3, 0x02, 0x80, 0xF6, // length 3, type 0x02 (creation time)
       0xFF, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
    ]).exact_view(),
  )
  assert_eq(subs.length(), 2)
  assert_eq(subs[0].sub_type, 0x02)
  assert_eq(subs[0].body().length(), 2)
  assert_eq(subs[1].sub_type, 0x01)
  assert_eq(subs[1].body().length(), 4)
}
