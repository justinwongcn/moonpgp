///|
/// Big-endian byte reader over a `BytesView`, used by every packet parser.
pub struct Reader {
  priv buf : BytesView
  priv mut pos : Int
} derive(Debug)

///|
pub fn Reader::new(buf : BytesView) -> Reader {
  Reader::{ buf, pos: 0, }
}

///|
pub fn Reader::remaining(self : Reader) -> Int {
  self.buf.length() - self.pos
}

///|
pub fn Reader::position(self : Reader) -> Int {
  self.pos
}

///|
pub fn Reader::view(self : Reader) -> BytesView {
  self.buf[self.pos:self.buf.length()]
}

///|
pub fn Reader::read_u8(self : Reader) -> Int raise {
  guard self.remaining() >= 1 else {
    raise @error.PgpError::PgpError(msg="packet: unexpected end of data (u8)")
  }
  let b = self.buf[self.pos].to_int()
  self.pos = self.pos + 1
  b
}

///|
pub fn Reader::read_u16(self : Reader) -> Int raise {
  guard self.remaining() >= 2 else {
    raise @error.PgpError::PgpError(msg="packet: unexpected end of data (u16)")
  }
  let v = (self.buf[self.pos].to_int() << 8) | self.buf[self.pos + 1].to_int()
  self.pos = self.pos + 2
  v
}

///|
pub fn Reader::read_u32(self : Reader) -> Int raise {
  guard self.remaining() >= 4 else {
    raise @error.PgpError::PgpError(msg="packet: unexpected end of data (u32)")
  }
  let v = (self.buf[self.pos].to_int() << 24) |
    (self.buf[self.pos + 1].to_int() << 16) |
    (self.buf[self.pos + 2].to_int() << 8) |
    self.buf[self.pos + 3].to_int()
  self.pos = self.pos + 4
  v
}

///|
pub fn Reader::read_bytes(self : Reader, n : Int) -> Bytes raise {
  guard n >= 0 && self.remaining() >= n else {
    raise @error.PgpError::PgpError(
      msg="packet: unexpected end of data (bytes, want \{n})",
    )
  }
  let out = self.buf[self.pos:self.pos + n].to_owned()
  self.pos = self.pos + n
  out
}

///|
pub fn Reader::read_rest(self : Reader) -> Bytes raise {
  self.read_bytes(self.remaining())
}

///|
/// Read an OpenPGP multiprecision integer (RFC 9580 §3.2).
pub fn Reader::read_mpi(self : Reader) -> Bytes raise {
  let bits = self.read_u16()
  let nbytes = (bits + 7) / 8
  self.read_bytes(nbytes)
}

///|
/// Read a scalar octet count of `n` octets (RFC 9580 §3.1).
pub fn Reader::read_scalar(self : Reader, n : Int) -> Int raise {
  match n {
    1 => self.read_u8()
    2 => self.read_u16()
    4 => self.read_u32()
    _ => raise @error.PgpError::PgpError(msg="packet: bad scalar length \{n}")
  }
}

///|
/// Big-endian byte writer for packet serialization.
pub struct Writer {
  priv out : Array[Byte]
} derive(Debug)

///|
pub fn Writer::new() -> Writer {
  Writer::{ out: [], }
}

///|
pub fn Writer::length(self : Writer) -> Int {
  self.out.length()
}

///|
pub fn Writer::u8(self : Writer, v : Int) -> Unit {
  self.out.push(v.to_byte())
}

///|
pub fn Writer::u16(self : Writer, v : Int) -> Unit {
  self.out.push((v >> 8).to_byte())
  self.out.push(v.to_byte())
}

///|
pub fn Writer::u32(self : Writer, v : Int) -> Unit {
  self.out.push((v >> 24).to_byte())
  self.out.push((v >> 16).to_byte())
  self.out.push((v >> 8).to_byte())
  self.out.push(v.to_byte())
}

///|
pub fn Writer::bytes(self : Writer, data : BytesView) -> Unit {
  for b in data {
    self.out.push(b)
  }
}

///|
pub fn Writer::mpi(self : Writer, data : BytesView) -> Unit {
  // Count significant bits: strip leading zero octets first.
  let mut start = 0
  while start < data.length() && data[start] == b'\x00' {
    start = start + 1
  }
  let stripped = data[start:data.length()]
  let bits = if stripped.length() == 0 {
    0
  } else {
    let lead = stripped[0].to_int()
    let mut b = 8
    while b > 1 {
      if (lead & (1 << (b - 1))) != 0 {
        break
      }
      b = b - 1
    }
    (stripped.length() - 1) * 8 + b
  }
  self.u16(bits)
  self.bytes(stripped)
}

///|
pub fn Writer::to_bytes(self : Writer) -> Bytes {
  Bytes::from_array(self.out)
}

///|
pub extend Reader with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Writer with @moonbitlang/core/debug.Debug::{to_repr}
