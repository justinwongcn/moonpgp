///|
fn hex_val(c : Int32) -> Int32? {
  if c >= 0x30 && c <= 0x39 {
    Some(c - 0x30)
  } else if c >= 0x41 && c <= 0x46 {
    Some(c - 0x41 + 10)
  } else if c >= 0x61 && c <= 0x66 {
    Some(c - 0x61 + 10)
  } else {
    None
  }
}

///|
/// RFC 2045 §6.7 quoted-printable decoding, byte-level and lenient:
/// `=XY` decodes to the byte, `=` at end of line (and of data) is a soft
/// break and is dropped, any other malformed sequence is kept literally.
pub fn decode_quoted_printable(data : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let n = data.length()
  let mut i = 0
  while i < n {
    let b = data[i]
    if b == b'=' {
      let c1 = if i + 1 < n { data[i + 1].to_int() } else { -1 }
      let c2 = if i + 2 < n { data[i + 2].to_int() } else { -1 }
      if c1 == 10 {
        // soft break over a bare LF
        i = i + 2
        continue
      }
      if c1 == 13 && c2 == 10 {
        // soft break over CRLF
        i = i + 3
        continue
      }
      match (hex_val(c1), hex_val(c2)) {
        (Some(h1), Some(h2)) => {
          out.push(((h1 << 4) | h2).to_byte())
          i = i + 3
        }
        _ =>
          if i + 1 >= n {
            // trailing '=' at end of data: transport padding, drop it
            i = i + 1
          } else {
            out.push(b)
            i = i + 1
          }
      }
    } else {
      out.push(b)
      i = i + 1
    }
  }
  Bytes::from_array(out)
}

///|
/// Decode a MIME body per its Content-Transfer-Encoding (RFC 2045 §6).
/// Identity encodings (7bit/8bit/binary, missing or unknown) pass the
/// bytes through unchanged — unknown encodings are tolerated like
/// gomime does instead of failing the whole message. base64 errors
/// surface as a raise so callers can degrade per part.
pub fn decode_transfer_encoding(data : BytesView, cte : String?) -> Bytes raise {
  let raw = match cte {
    Some(s) => s
    None => ""
  }
  // Tolerate anything after ';' though the header carries no parameters.
  let name = match raw.split_once(";") {
    Some((head, _)) => head.trim().to_owned().to_lower()
    None => raw.trim().to_owned().to_lower()
  }
  match name {
    "" | "7bit" | "8bit" | "binary" => data.to_owned()
    "quoted-printable" => decode_quoted_printable(data)
    "base64" => {
      let text = @utf8.decode_lossy(data)
      @base64.decode(text, ignore_whitespace=true) catch {
        _ => @error.fail("mime: invalid base64 body")
      }
    }
    _ => data.to_owned()
  }
}
