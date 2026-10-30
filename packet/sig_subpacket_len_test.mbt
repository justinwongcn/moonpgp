///|
/// Hashed-area subpacket length validation (RFC 9580 §5.2.3.4/.6/.10/.29):
/// a wrong-length semantic subpacket must be a parse error, not a silent
/// "absent" that reads as "never expires" or "all capabilities".

///|
/// Craft a minimal v4 RSA signature packet body: header fields, a hashed
/// area carrying `subpackets`, an empty unhashed area and a fast hash.
/// Parsing is expected to fail inside the hashed-area validation, before
/// the trailing signature parameters are read.
fn sig_body_with_hashed(hashed : Array[Byte]) -> Bytes {
  let b : Array[Byte] = [4, 0, 1, 8]
  let n = hashed.length()
  b.push(((n >> 8) & 0xFF).to_byte())
  b.push((n & 0xFF).to_byte())
  for x in hashed {
    b.push(x)
  }
  // unhashed area length 0
  b.push(0)
  b.push(0)
  // fast hash
  b.push(0xAA)
  b.push(0xBB)
  Bytes::from_array(b)
}

///|
test "a 3-octet creation time is malformed, not 'no creation time'" {
  // subpacket: length 4 (type octet + 3), type 2 (creation time), 3 bytes
  let body = sig_body_with_hashed([4, 2, 0x01, 0x02, 0x03])
  let raised = try {
    let _ = @packet.SignaturePacket::parse(body.exact_view())
    false
  } catch {
    @error.PgpError::Malformed(msg~) => msg.contains("invalid body length")
    _ => false
  }
  assert_true(raised)
}

///|
test "a type-only Key Flags subpacket is malformed, not 'all capabilities'" {
  // subpacket: length 1 (type octet only), type 27 (key flags), no body
  let body = sig_body_with_hashed([1, 27])
  let raised = try {
    let _ = @packet.SignaturePacket::parse(body.exact_view())
    false
  } catch {
    @error.PgpError::Malformed(msg~) => msg.contains("invalid body length")
    _ => false
  }
  assert_true(raised)
}

///|
test "a well-formed creation time passes validation" {
  // 4-octet creation time: length 5, type 2, big-endian timestamp
  let body = sig_body_with_hashed([5, 2, 0x5F, 0x00, 0x00, 0x01])
  // The packet still fails overall (truncated signature parameters),
  // but the failure must come from later parsing, not from the
  // subpacket-length validator.
  let not_validator = try {
    let _ = @packet.SignaturePacket::parse(body.exact_view())
    true
  } catch {
    @error.PgpError::Malformed(msg~) => !msg.contains("invalid body length")
    _ => false
  }
  assert_true(not_validator)
}
