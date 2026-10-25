///|
/// Kinds of ASCII armor (RFC 9580 §6.2). Cleartext-signed messages are not
/// armor blocks themselves (their enclosed signature is), so there is no
/// CleartextMessage variant — decode never produces one and cleartext
/// handling lives in `@api.cleartext`.
pub(all) enum ArmorType {
  Message
  PublicKey
  PrivateKey
  Signature
} derive(Eq, Debug)

///|
pub fn ArmorType::begin_marker(self : ArmorType) -> String {
  match self {
    Message => "-----BEGIN PGP MESSAGE-----"
    PublicKey => "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    PrivateKey => "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    Signature => "-----BEGIN PGP SIGNATURE-----"
  }
}

///|
pub fn ArmorType::end_marker(self : ArmorType) -> String {
  match self {
    Message => "-----END PGP MESSAGE-----"
    PublicKey => "-----END PGP PUBLIC KEY BLOCK-----"
    PrivateKey => "-----END PGP PRIVATE KEY BLOCK-----"
    Signature => "-----END PGP SIGNATURE-----"
  }
}

///|
/// True when `line` is exactly the marker, modulo trailing spaces/tabs.
/// Whole-line equality (S8): a BEGIN marker with trailing garbage on the
/// line ("-----BEGIN PGP MESSAGE-----ANYTHING") is not an armor block.
fn line_is_marker(line : StringView, marker : String) -> Bool {
  let mut end = line.length()
  while end > 0 {
    let c = line[end - 1]
    if c == ' ' || c == '\t' {
      end = end - 1
    } else {
      break
    }
  }
  line[0:end].to_owned() == marker
}

///|
fn armor_type_of_begin(line : StringView) -> ArmorType? {
  if line_is_marker(line, "-----BEGIN PGP MESSAGE-----") {
    Some(Message)
  } else if line_is_marker(line, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
    Some(PublicKey)
  } else if line_is_marker(line, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
    Some(PrivateKey)
  } else if line_is_marker(line, "-----BEGIN PGP SIGNATURE-----") {
    Some(Signature)
  } else {
    None
  }
}

///|
/// A decoded armor block: armor type, armor headers, and payload bytes.
pub struct ArmorBlock {
  armor_type : ArmorType
  /// Armor headers in order of appearance (e.g. "Version", "Comment").
  headers : Array[(String, String)]
  data : Bytes
} derive(Debug)

///|
pub fn ArmorBlock::armor_type(self : ArmorBlock) -> ArmorType {
  self.armor_type
}

///|
pub fn ArmorBlock::data(self : ArmorBlock) -> Bytes {
  self.data
}

///|
/// Look up an armor header value (first occurrence wins, case-insensitive key).
pub fn ArmorBlock::header(self : ArmorBlock, key : String) -> String? {
  for pair in self.headers {
    if pair.0.to_lower() == key.to_lower() {
      return Some(pair.1)
    }
  }
  None
}

///|
/// Version header emitted when the caller does not supply one.
const VERSION_STRING : String = "moonpgp 0.1.0"

///|
/// Encode `data` into ASCII armor with this block type and headers.
pub fn ArmorType::encode(
  self : ArmorType,
  data : BytesView,
  headers? : Array[(String, String)],
) -> String {
  let buf = StringBuilder()
  buf.write_string(self.begin_marker())
  buf.write_char('\n')
  let mut have_version = false
  match headers {
    Some(hs) =>
      for pair in hs {
        buf.write_string(pair.0)
        buf.write_string(": ")
        buf.write_string(pair.1)
        buf.write_char('\n')
        if pair.0.to_lower() == "version" {
          have_version = true
        }
      }
    None => ()
  }
  if !have_version {
    buf.write_string("Version: ")
    buf.write_string(VERSION_STRING)
    buf.write_char('\n')
  }
  buf.write_char('\n')
  let b64 = @base64.encode(data)
  let mut i = 0
  while i < b64.length() {
    let end = if i + 64 < b64.length() { i + 64 } else { b64.length() }
    buf.write_stringview(b64[i:end])
    buf.write_char('\n')
    i = i + 64
  }
  let crc = crc24(data)
  let crc_bytes = Bytes::makei(3, i => (crc >> (16 - i * 8)).to_byte())
  buf.write_char('=')
  buf.write_string(@base64.encode(crc_bytes))
  buf.write_char('\n')
  buf.write_string(self.end_marker())
  buf.write_char('\n')
  buf.to_string()
}

///|
/// Convenience for `Message.encode(data)`.
pub fn encode(data : BytesView, headers? : Array[(String, String)]) -> String {
  Message.encode(data, headers?)
}

///|
/// Decode the first armor block found anywhere in `text` (leading garbage
/// such as a cleartext-signed body is skipped). The CRC line, when present,
/// is verified.
pub fn decode(text : String) -> ArmorBlock raise {
  let blocks = decode_all(text)
  blocks[0]
}

///|
/// Decode every armor block in `text`, in order.
pub fn decode_all(text : String) -> Array[ArmorBlock] raise {
  let blocks : Array[ArmorBlock] = []
  // Normalize CRLF before splitting: armor files (and mail) often carry
  // Windows line endings.
  let normalized = text.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let n = lines.length()
  let mut i = 0
  while i < n {
    let line = lines[i]
    match armor_type_of_begin(line) {
      None => i = i + 1
      Some(armor_type) => {
        i = i + 1
        // Armor headers until a blank line (or directly the body if none).
        let headers : Array[(String, String)] = []
        while i < n && !lines[i].has_prefix("-----") {
          let l = lines[i]
          if l == "" {
            i = i + 1
            break
          }
          match l.split_once(": ") {
            Some((k, v)) => headers.push((k.to_owned(), v.to_owned()))
            None =>
              // Tolerate headers without a space after the colon.
              match l.split_once(":") {
                Some((k, v)) => headers.push((k.to_owned(), v.to_owned()))
                None => ()
              }
          }
          i = i + 1
        }
        // Base64 body until the CRC line or the END marker.
        let body = StringBuilder()
        let mut crc : Int32? = None
        let mut closed = false
        while i < n {
          let l = lines[i]
          if l.has_prefix("-----END PGP") {
            closed = true
            i = i + 1
            break
          } else if l.has_prefix("-----BEGIN PGP") {
            // Malformed input; treat as end to avoid an infinite mess.
            break
          } else if l.has_prefix("=") && !body.is_empty() {
            match parse_crc_line(l) {
              Some(c) => crc = Some(c)
              // A "=" line that does not parse as a CRC must not be dropped:
              // silently skipping it would bypass the integrity check.
              None => @error.fail("armor: malformed CRC line")
            }
          } else {
            body.write_stringview(l)
          }
          i = i + 1
        }
        if !closed {
          @error.fail(
            "armor: missing END marker after \{armor_type.begin_marker()}",
          )
        }
        let data = @base64.decode(body.to_string(), ignore_whitespace=true) catch {
          _ => @error.fail("armor: invalid base64 body")
        }
        match crc {
          Some(expected) =>
            if expected != crc24(data.exact_view()) {
              @error.fail("armor: CRC-24 mismatch")
            }
          None => ()
        }
        blocks.push(ArmorBlock::{ armor_type, headers, data, })
      }
    }
  }
  if blocks.is_empty() {
    @error.fail("armor: no armor block found")
  }
  blocks
}

///|
fn parse_crc_line(line : StringView) -> Int32? {
  let body = line.strip_prefix("=")
  match body {
    None => None
    Some(s) =>
      try {
        let b = @base64.decode(s.to_owned())
        if b.length() == 3 {
          Some((b[0].to_int() << 16) | (b[1].to_int() << 8) | b[2].to_int())
        } else {
          None
        }
      } catch {
        _ => None
      }
  }
}

///|
pub extend ArmorBlock with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend ArmorType with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend ArmorType with Eq::{not_equal, equal}
