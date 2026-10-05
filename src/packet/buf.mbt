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
    @error.fail("packet: unexpected end of data (u8)")
  }
  let b = self.buf[self.pos].to_int()
  self.pos = self.pos + 1
  b
}

///|
pub fn Reader::read_u16(self : Reader) -> Int raise {
  guard self.remaining() >= 2 else {
    @error.fail("packet: unexpected end of data (u16)")
  }
  let v = (self.buf[self.pos].to_int() << 8) | self.buf[self.pos + 1].to_int()
  self.pos = self.pos + 2
  v
}

///|
/// Read a big-endian u32 into a 32-bit Int (F09, documented convention):
/// values ≥ 2³¹ arrive NEGATIVE. Length paths fail safe through the
/// `n >= 0` checks in `read_bytes` (with a misleading "want -N" message);
/// timestamp paths carry the correct two's-complement wire value, which
/// `Writer::u32` reproduces byte-exactly on re-serialization.
pub fn Reader::read_u32(self : Reader) -> Int raise {
  guard self.remaining() >= 4 else {
    @error.fail("packet: unexpected end of data (u32)")
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
    @error.fail("packet: unexpected end of data (bytes, want \{n})")
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
/// Big-endian byte writer for packet serialization. The backing buffer is
/// core's `Buffer` so `bytes()` can bulk-write views instead of pushing
/// byte by byte (F12).
pub struct Writer {
  priv out : Buffer
} derive(Debug)

///|
pub fn Writer::new() -> Writer {
  Writer::{ out: Buffer(size_hint=256), }
}

///|
pub fn Writer::length(self : Writer) -> Int {
  self.out.length()
}

///|
pub fn Writer::u8(self : Writer, v : Int) -> Unit {
  self.out.write_byte(v.to_byte())
}

///|
pub fn Writer::u16(self : Writer, v : Int) -> Unit {
  self.out.write_byte((v >> 8).to_byte())
  self.out.write_byte(v.to_byte())
}

///|
pub fn Writer::u32(self : Writer, v : Int) -> Unit {
  self.out.write_byte((v >> 24).to_byte())
  self.out.write_byte((v >> 16).to_byte())
  self.out.write_byte((v >> 8).to_byte())
  self.out.write_byte(v.to_byte())
}

///|
pub fn Writer::bytes(self : Writer, data : BytesView) -> Unit {
  self.out.write_bytes(data)
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
  self.out.to_bytes()
}

///|
pub extend Reader with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Writer with @moonbitlang/core/debug.Debug::{to_repr}
