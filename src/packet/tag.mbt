///|
/// OpenPGP packet type IDs (RFC 9580 §5).
pub(all) enum PacketTag {
  Pkesk
  Skesk
  Signature
  OnePassSig
  SecretKey
  PublicKey
  SecretSubkey
  Compressed
  Sed
  Marker
  Literal
  Trust
  UserId
  PublicSubkey
  UserAttribute
  Seipd
  Mdc
  AeadEncData
  Unknown(Int)
} derive(Eq, Debug)

///|
pub fn PacketTag::number(self : PacketTag) -> Int {
  match self {
    Pkesk => 1
    Signature => 2
    Skesk => 3
    OnePassSig => 4
    SecretKey => 5
    PublicKey => 6
    SecretSubkey => 7
    Compressed => 8
    Sed => 9
    Marker => 10
    Literal => 11
    Trust => 12
    UserId => 13
    PublicSubkey => 14
    UserAttribute => 17
    Seipd => 18
    Mdc => 19
    AeadEncData => 20
    Unknown(n) => n
  }
}

///|
pub fn tag_of_number(n : Int) -> PacketTag {
  match n {
    1 => Pkesk
    2 => Signature
    3 => Skesk
    4 => OnePassSig
    5 => SecretKey
    6 => PublicKey
    7 => SecretSubkey
    8 => Compressed
    9 => Sed
    10 => Marker
    11 => Literal
    12 => Trust
    13 => UserId
    14 => PublicSubkey
    17 => UserAttribute
    18 => Seipd
    19 => Mdc
    20 => AeadEncData
    _ => Unknown(n)
  }
}

///|
/// One parsed packet: type plus the raw packet body (header stripped).
/// Higher-level parsers decode bodies into typed structures.
pub(all) struct RawPacket {
  tag : PacketTag
  body : Bytes
} derive(Debug)

///|
pub fn RawPacket::tag(self : RawPacket) -> PacketTag {
  self.tag
}

///|
pub fn RawPacket::body(self : RawPacket) -> Bytes {
  self.body
}

///|
/// Parse a sequence of packet headers+bodies from `data`. Handles both old
/// and new format headers and accumulates partial body lengths.
pub fn parse_packets(data : BytesView) -> Array[RawPacket] raise {
  let packets : Array[RawPacket] = []
  let r = Reader::new(data)
  while r.remaining() > 0 {
    packets.push(read_one_packet(r))
  }
  packets
}

///|
/// Serialize one packet with a new-format header.
pub fn serialize_packet(tag : PacketTag, body : BytesView) -> Bytes {
  let w = Writer::new()
  w.u8(0xC0 | tag.number())
  write_new_length(w, body.length())
  w.bytes(body)
  w.to_bytes()
}

///|
/// Serialize one packet with an old-format header and fixed-length encoding.
pub fn serialize_packet_old(tag : PacketTag, body : BytesView) -> Bytes {
  let w = Writer::new()
  let len = body.length()
  let mode : Int = if len < 256 { 0 } else if len < 65536 { 1 } else { 2 }
  w.u8(0x80 | (tag.number() << 2) | mode)
  write_old_length(w, len)
  w.bytes(body)
  w.to_bytes()
}

///|
fn write_new_length(w : Writer, length : Int) -> Unit {
  if length < 192 {
    w.u8(length)
  } else if length < 8384 {
    let enc = length - 192 + 192 * 256
    w.u8(enc >> 8)
    w.u8(enc)
  } else {
    w.u8(255)
    w.u32(length)
  }
}

///|
fn write_old_length(w : Writer, length : Int) -> Unit {
  if length < 256 {
    w.u8(length)
  } else if length < 65536 {
    w.u16(length)
  } else {
    w.u32(length)
  }
}

///|
fn read_one_packet(r : Reader) -> RawPacket raise {
  guard r.remaining() >= 2 else {
    raise @error.PgpError::PgpError(msg="packet: truncated header")
  }
  let first = r.read_u8()
  guard (first & 0x80) != 0 else {
    raise @error.PgpError::PgpError(msg="packet: invalid header octet \{first}")
  }
  let tag : PacketTag = if (first & 0x40) != 0 {
    // New format.
    tag_of_number(first & 0x3F)
  } else {
    // Old format.
    tag_of_number((first >> 2) & 0x0F)
  }
  let chunks : Array[Bytes] = []
  if (first & 0x40) != 0 {
    // New format lengths.
    while true {
      let len = read_new_length(r)
      if len < 0 {
        chunks.push(r.read_bytes(-len - 1))
      } else {
        chunks.push(r.read_bytes(len))
        break
      }
    }
  } else {
    // Old format lengths: 0,1,2,3 = 1,2,4 octets or indeterminate.
    let mode = first & 0x03
    match mode {
      0 => chunks.push(r.read_bytes(r.read_u8()))
      1 => chunks.push(r.read_bytes(r.read_u16()))
      2 => chunks.push(r.read_bytes(r.read_u32()))
      _ =>
        // Mode 3: indeterminate length; body runs to the end of the container.
        chunks.push(r.read_rest())
    }
  }
  let body : Bytes = if chunks.length() == 1 {
    chunks[0]
  } else {
    let mut all = Bytes::new(0)
    for c in chunks {
      all = all.add(c)
    }
    all
  }
  RawPacket::{ tag, body, }
}

///|
/// Returns the length, or `-(code)-1` for a partial length code.
fn read_new_length(r : Reader) -> Int raise {
  let first = r.read_u8()
  if first < 192 {
    first
  } else if first < 224 {
    let second = r.read_u8()
    ((first - 192) << 8) + second + 192
  } else if first < 255 {
    // Partial body length: 1 << (first & 0x1F) octets.
    -(1 << (first & 0x1F)) - 1
  } else {
    r.read_u32()
  }
}
