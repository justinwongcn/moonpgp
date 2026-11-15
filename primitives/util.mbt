///|
/// Constant-time byte-string comparison for secret material (key check
/// sums, MAC tags). Length mismatch returns `false` immediately; content
/// comparison itself leaks nothing beyond the length.
pub fn ct_equal(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
/// Left-pad `data` with zeros to `size` bytes (i2osp helper for fixed-width
/// integers).
pub fn pad_left(data : BytesView, size : Int32) -> Bytes {
  let pad = size - data.length()
  if pad <= 0 {
    return data.to_owned()
  }
  let out : Array[Byte] = Array(capacity=size)
  for _ in 0..<pad {
    out.push(b'\x00')
  }
  for b in data {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// Right-pad `data` with zeros to `size` bytes.
pub fn pad_right(data : BytesView, size : Int32) -> Bytes {
  if data.length() >= size {
    return data.to_owned()
  }
  let out : Array[Byte] = Array(capacity=size)
  for b in data {
    out.push(b)
  }
  for _ in data.length()..<size {
    out.push(b'\x00')
  }
  Bytes::from_array(out)
}

///|
/// Concatenate two byte strings.
pub fn concat2(a : BytesView, b : BytesView) -> Bytes {
  a.to_owned().add(b.to_owned())
}

///|
/// Concatenate three byte strings.
pub fn concat3(a : BytesView, b : BytesView, c : BytesView) -> Bytes {
  concat2(a, concat2(b, c))
}

///|
/// Concatenate four byte strings.
pub fn concat4(
  a : BytesView,
  b : BytesView,
  c : BytesView,
  d : BytesView,
) -> Bytes {
  concat2(concat2(a, b), concat2(c, d))
}

///|
/// XOR two equally long byte strings.
pub fn xor_bytes(a : BytesView, b : BytesView) -> Bytes raise {
  guard a.length() == b.length() else {
    @error.fail("xor_bytes: length mismatch")
  }
  Bytes::makei(a.length(), i => a[i] ^ b[i])
}

///|
/// Lowercase hex encoding (test vectors, fingerprints, key ids).
pub fn to_hex(data : BytesView) -> String {
  @hex.encode(data)
}

///|
/// Parse a lowercase/uppercase hex string.
pub fn from_hex(s : String) -> Bytes raise {
  @hex.decode(s) catch {
    _ => @error.malformed("invalid hex string")
  }
}

///|
/// UTF-8 encoding of a string for PGP wire use (User IDs, passphrases,
/// literal file names). `String::to_bytes`/`Bytes::of_string` are UTF-16LE
/// and must never be used on wire material.
///
/// A lone surrogate — the one way a MoonBit String can be invalid — makes
/// core's encoder ABORT the process, uncatchable for embedders (audit
/// api6). The check lives at this shared chokepoint so every text entry
/// fails with a catchable error instead. Valid surrogate pairs encode as
/// before; the scan runs in code-unit space (`s[i]`, the F22 lesson).
pub fn utf8_bytes(s : String) -> Bytes raise {
  let mut expect_low = false
  for i in 0..<s.length() {
    let v = s[i]
    if expect_low {
      guard v >= 0xDC00 && v <= 0xDFFF else {
        @error.malformed("utf8: lone high surrogate in text input")
      }
      expect_low = false
    } else if v >= 0xD800 && v <= 0xDBFF {
      expect_low = true
    } else if v >= 0xDC00 && v <= 0xDFFF {
      @error.malformed("utf8: lone low surrogate in text input")
    }
  }
  guard !expect_low else {
    @error.malformed("utf8: lone high surrogate in text input")
  }
  @utf8.encode(s)
}
