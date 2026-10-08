///|
fn push_hex(out : Array[Byte], b : Int) -> Unit {
  out.push(b'=')
  let hi = b >> 4
  let lo = b & 15
  out.push((if hi < 10 { 48 + hi } else { 55 + hi }).to_byte())
  out.push((if lo < 10 { 48 + lo } else { 55 + lo }).to_byte())
}

///|
/// RFC 2045 §6.7 quoted-printable encoding (the write side of
/// mime.decode_quoted_printable). CRLF passes through as a hard break;
/// printable bytes stay literal; `=` and non-printables become =XX;
/// trailing space/tab before a break is encoded; soft breaks `=\r\n`
/// keep every line ≤ 76 chars and never split an =XX atom.
pub fn encode_quoted_printable(data : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let n = data.length()
  let mut col = 0
  let mut i = 0
  while i < n {
    let b = data[i].to_int()
    if b == 13 && i + 1 < n && data[i + 1].to_int() == 10 {
      // hard break: CRLF passes through
      out.push(b'\r')
      out.push(b'\n')
      col = 0
      i = i + 2
      continue
    }
    let mut literal = -1
    let mut alen = 3
    if b == 13 || b == 10 || b == 61 {
      // lone CR/LF and '=' always encoded
      literal = -1
    } else if b == 9 || b == 32 {
      // WSP is literal unless it terminates the line (or the data)
      let at_end = i + 1 >= n ||
        data[i + 1].to_int() == 13 ||
        data[i + 1].to_int() == 10
      if !at_end {
        literal = b
        alen = 1
      }
    } else if b >= 33 && b <= 126 {
      literal = b
      alen = 1
    }
    // soft break BEFORE the atom so =XX never splits; the '=' of the
    // break itself must fit: 75 + 1 = 76 chars max per line
    if col + alen > 75 {
      out.push(b'=')
      out.push(b'\r')
      out.push(b'\n')
      col = 0
    }
    if literal >= 0 {
      out.push(literal.to_byte())
    } else {
      push_hex(out, b)
    }
    col = col + alen
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
/// Bytes → ASCII String (QP output is pure ASCII by construction).
fn bytes_to_ascii(data : BytesView) -> String {
  let sb = StringBuilder()
  for b in data {
    match b.to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
  }
  sb.to_string()
}
