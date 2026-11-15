///|
/// RFC 2047 encoded-word support for message headers (Subject, display
/// names): `=?utf-8?B?<base64>?=` with the 75-octet encoded-word limit.
///
/// Scope: B-encoding on output; B and Q on input. Charsets other than
/// utf-8/us-ascii are passed through untouched (conservative). CR/LF and
/// other control characters are rejected on encode — the header-injection
/// guard that `require_ascii` used to provide.

///|
fn require_no_ctl(s : String, what : String) -> Unit raise {
  for c in s {
    let v = c.to_int()
    // C1 controls (U+0080–U+009F) and DEL ride through a bare `>= 32`
    // check (audit F21 residual): UTF-8 CSI (U+009B) executes as a
    // terminal escape, NEL (U+0085) forges list rows. é (U+00E9) and
    // every real non-ASCII character sit above the C1 band and pass.
    guard v >= 32 && v != 0x7F && !(v >= 0x80 && v <= 0x9F) else {
      @error.fail("mail: control character in \{what} (header injection?)")
    }
  }
}

///|
fn is_ascii_printable(s : String) -> Bool {
  for c in s {
    let v = c.to_int()
    if v < 32 || v > 127 {
      return false
    }
  }
  true
}

///|
/// Max UTF-8 bytes per encoded word: "=?utf-8?B?" (10) + base64
/// (ceil(n/3)*4) + "?=" (2) must stay ≤ 75, so n ≤ 47.25. The chunker
/// splits before lead bytes only, so a chunk grows by at most 3 extra
/// continuation octets; 45 keeps every word ≤ 72 octets.
const RFC2047_CHUNK_BYTES : Int32 = 45

///|
fn flush_encoded_word(buf : StringBuilder, chunk : Array[Byte]) -> Unit {
  buf.write_string("=?utf-8?B?")
  buf.write_string(@base64.encode(Bytes::from_array(chunk)))
  buf.write_string("?=")
}

///|
/// Encode a header value for the wire: printable ASCII passes through
/// unchanged; anything else becomes one or more `=?utf-8?B?...?=` words
/// joined by single spaces (decoders ignore that whitespace between
/// adjacent encoded words).
pub fn encode_rfc2047(value : String) -> String raise {
  require_no_ctl(value, "header value")
  if is_ascii_printable(value) {
    return value
  }
  let bytes = @utf8.encode(value)
  let buf = StringBuilder()
  let chunk : Array[Byte] = []
  let mut first = true
  for b in bytes {
    // Split only before a UTF-8 lead byte so multibyte characters stay
    // whole even when other implementations split mid-character.
    if chunk.length() >= RFC2047_CHUNK_BYTES && (b.to_int() & 0xC0) != 0x80 {
      if !first {
        buf.write_char(' ')
      }
      flush_encoded_word(buf, chunk)
      first = false
      chunk.clear()
    }
    chunk.push(b)
  }
  if chunk.length() > 0 {
    if !first {
      buf.write_char(' ')
    }
    flush_encoded_word(buf, chunk)
  }
  buf.to_string()
}

///|
fn hex_val(c : Char) -> Int32? {
  let v = c.to_int()
  if v >= 0x30 && v <= 0x39 {
    Some(v - 0x30)
  } else if v >= 0x41 && v <= 0x46 {
    Some(v - 0x41 + 10)
  } else if v >= 0x61 && v <= 0x66 {
    Some(v - 0x61 + 10)
  } else {
    None
  }
}

///|
/// C0 control characters are stripped from decoded output (audit F21):
/// the ENCODE side has required their absence since `require_no_ctl`, but
/// a B-encoded word can carry CR/LF/ESC past it — and a terminal-fed
/// From/Subject line then forges list rows or injects escape sequences.
/// Tab survives (legal folding whitespace).
fn strip_ctl(bytes : Bytes) -> Bytes {
  let out : Array[Byte] = []
  for b in bytes {
    let v = b.to_int()
    if v >= 0x20 || v == 0x09 {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}

///|
/// Decode one encoded word body with the given transfer encoding
/// (B = base64, Q = quoted-printable variant with `_` for space).
fn decode_word_data(enc : String, data : String) -> Bytes? {
  match enc {
    "B" | "b" =>
      Some(strip_ctl(@base64.decode(data) catch { _ => return None }))
    "Q" | "q" => {
      let bytes : Array[Byte] = []
      let chars : Array[Char] = data.iter().collect()
      let mut i = 0
      while i < chars.length() {
        let c = chars[i]
        if c == '_' {
          bytes.push(b'\x20')
          i = i + 1
        } else if c == '=' && i + 2 < chars.length() {
          match (hex_val(chars[i + 1]), hex_val(chars[i + 2])) {
            (Some(h), Some(l)) => {
              bytes.push((h * 16 + l).to_byte())
              i = i + 3
            }
            _ => {
              bytes.push(c.to_int().to_byte())
              i = i + 1
            }
          }
        } else {
          // Q permits only printable ASCII; anything else passes raw.
          bytes.push(c.to_int().to_byte())
          i = i + 1
        }
      }
      Some(strip_ctl(Bytes::from_array(bytes)))
    }
    _ => None
  }
}

///|
/// RFC 2047 §2 caps an encoded word at 75 octets and real encoders stay
/// at or under it; a scan window with no "?=" inside this bound is not
/// an encoded word. The bound keeps the decoder linear (F-R3: every
/// opener used to rescan the whole remaining header — quadratic).
const MAX_ENCODED_WORD_CHARS : Int32 = 99

///|
/// Try to parse an encoded word at char position `start`. Returns the
/// decoded bytes and the position just past the closing `?=`.
fn try_parse_encoded_word(
  chars : Array[Char],
  start : Int32,
) -> (Bytes, Int32)? {
  guard start + 1 < chars.length() &&
    chars[start] == '=' &&
    chars[start + 1] == '?' else {
    return None
  }
  // =?charset?enc?data?= — encoded-text contains no '?', so the first
  // "?=" closes the word.
  let parts : Array[String] = []
  let buf = StringBuilder()
  let limit = start + MAX_ENCODED_WORD_CHARS
  let mut i = start + 2
  while i < chars.length() && i < limit {
    if chars[i] == '?' {
      parts.push(buf.to_string())
      buf.reset()
      if i + 1 < chars.length() && chars[i + 1] == '=' {
        // Closing "?=".
        guard parts.length() == 3 else { return None }
        let charset = parts[0].to_lower()
        guard charset == "utf-8" || charset == "us-ascii" else { return None }
        let decoded = decode_word_data(parts[1], parts[2])
        match decoded {
          Some(b) => return Some((b, i + 2))
          None => return None
        }
      }
      i = i + 1
    } else {
      buf.write_char(chars[i])
      i = i + 1
    }
  }
  None
}

///|
fn is_lwsp_char(c : Char) -> Bool {
  c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

///|
/// Append the UTF-8 bytes of `s` to the byte accumulator.
fn acc_append(acc : Array[Byte], s : String) -> Unit {
  for b in @utf8.encode(s) {
    acc.push(b)
  }
}

///|
/// Flush the byte accumulator into `out` (decoded words concatenate at
/// byte level because a multibyte character may span encoded words).
fn acc_flush(out : StringBuilder, acc : Array[Byte]) -> Unit {
  if acc.length() > 0 {
    out.write_string(@utf8.decode_lossy(Bytes::from_array(acc).exact_view()))
    acc.clear()
  }
}

///|
/// Output-boundary control-character filter (audit F21 residual). The
/// byte-level `strip_ctl` only sees encoded-word payloads; raw header
/// text reaches the output verbatim, C1 controls survive the byte filter
/// inside multibyte sequences, and DEL passes both (`>= 0x20`). The
/// filter therefore runs once on the assembled string — the only point
/// every path (raw text, pending gaps, cross-word byte reassembly)
/// converges. Tab survives (legal folding whitespace).
fn strip_ctl_string(s : String) -> String {
  let out = StringBuilder()
  for c in s {
    let v = c.to_int()
    if v == 0x09 || (v >= 0x20 && v != 0x7F && !(v >= 0x80 && v <= 0x9F)) {
      out.write_char(c)
    }
  }
  out.to_string()
}

///|
/// Strip terminal-hostile control characters (C0 except tab, DEL, the
/// C1 band) from server-supplied text destined for a terminal. Same
/// discipline as the decode_rfc2047 output filter (audit F21 + hacker
/// round), exposed for callers that print OTHER server-controlled
/// fields (IMAP flags, dates) next to decoded headers — a hostile
/// server otherwise escapes the same terminal through the sibling
/// field.
pub fn sanitize_terminal(s : String) -> String {
  strip_ctl_string(s)
}

///|
/// Decode RFC 2047 encoded words in a header value. Whitespace between
/// adjacent encoded words is dropped (RFC 2047 §6.2). Unsupported
/// charsets pass through as raw text.
pub fn decode_rfc2047(value : String) -> String {
  let chars : Array[Char] = value.iter().collect()
  let out = StringBuilder()
  let acc : Array[Byte] = []
  let mut i = 0
  let mut last_was_word = false
  let pending = StringBuilder()
  while i < chars.length() {
    match try_parse_encoded_word(chars, i) {
      Some((bytes, next)) => {
        let gap = pending.to_string()
        if gap != "" {
          // LWSP between two adjacent encoded words is ignored.
          let only_lwsp = gap.iter().all(is_lwsp_char)
          if !(last_was_word && only_lwsp) {
            acc_append(acc, gap)
          }
          pending.reset()
        }
        for b in bytes {
          acc.push(b)
        }
        last_was_word = true
        i = next
      }
      None => {
        let c = chars[i]
        if last_was_word {
          pending.write_char(c)
        } else {
          acc_flush(out, acc)
          out.write_char(c)
        }
        // F-R3: a failed attempt already scanned its whole bounded
        // window. When this position was an opener, skip past "?=" — the
        // position in between is a '?' and cannot open a word, so the
        // skip is lossless and the same window is not re-scanned from
        // one character later. The skipped '?' still belongs to the raw
        // passthrough (unsupported charsets fall back to verbatim text).
        if c == '=' && i + 1 < chars.length() && chars[i + 1] == '?' {
          if last_was_word {
            pending.write_char(chars[i + 1])
          } else {
            out.write_char(chars[i + 1])
          }
          i = i + 2
        } else {
          i = i + 1
        }
      }
    }
  }
  if !pending.is_empty() {
    acc_append(acc, pending.to_string())
  }
  acc_flush(out, acc)
  strip_ctl_string(out.to_string())
}
