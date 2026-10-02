///|
/// Parsed Content-Type value (RFC 2045 §5). `main_type`/`sub_type` are
/// lowercased; parameter keys are lowercased while values keep their
/// original case (boundary values are case-sensitive per RFC 2046 §5.1.1).
pub struct MediaType {
  main_type : String
  sub_type : String
  params : Array[(String, String)]
} derive(Debug)

///|
pub fn MediaType::mimetype(self : MediaType) -> String {
  self.main_type + "/" + self.sub_type
}

///|
/// Parameter lookup by case-insensitive name. Later occurrences win,
/// matching Go's mime.ParseMediaType (which gopenpgp builds on).
pub fn MediaType::param(self : MediaType, name : String) -> String? {
  param_of(self.params, name)
}

///|
fn param_of(params : Array[(String, String)], name : String) -> String? {
  let lower = name.to_lower()
  let mut found : String? = None
  for pair in params {
    if pair.0 == lower {
      found = Some(pair.1)
    }
  }
  found
}

///|
/// RFC 2045 §5.2 default for parts without a Content-Type header.
fn default_media_type() -> MediaType {
  MediaType::{ main_type: "text", sub_type: "plain", params: [], }
}

///|
/// Shared parsing for header values shaped `token; k=v; k="v"` (used by
/// Content-Type and Content-Disposition). The token is trimmed and
/// lowercased; parameter keys are lowercased, quoted values keep their
/// original case and resolve quoted-pair escapes (`\X`, RFC 2045 §5.1).
/// Later duplicate keys win. Semicolons inside quoted strings do not
/// split. Empty segments (trailing `;`) are tolerated.
pub fn parse_header_params(
  value : String,
) -> (String, Array[(String, String)]) raise {
  let chars : Array[Char] = []
  for ch in value {
    chars.push(ch)
  }
  let n = chars.length()
  let params : Array[(String, String)] = []
  let tokbuf = StringBuilder()
  let mut i = 0
  while i < n && chars[i] != ';' {
    tokbuf.write_char(chars[i])
    i = i + 1
  }
  let token = tokbuf.to_string().trim().to_owned().to_lower()
  while i < n {
    // chars[i] == ';': a new parameter segment follows.
    i = i + 1
    while i < n && (chars[i] == ' ' || chars[i] == '\t') {
      i = i + 1
    }
    let keybuf = StringBuilder()
    while i < n && chars[i] != '=' && chars[i] != ';' {
      keybuf.write_char(chars[i])
      i = i + 1
    }
    let key = keybuf.to_string().trim().to_owned().to_lower()
    if i >= n || chars[i] == ';' {
      // Segment without '=': tolerate empty ones, reject named ones.
      guard key == "" else {
        raise @error.PgpError::PgpError(msg="mime: parameter without value")
      }
      continue
    }
    guard key != "" else {
      raise @error.PgpError::PgpError(msg="mime: empty parameter name")
    }
    i = i + 1
    while i < n && (chars[i] == ' ' || chars[i] == '\t') {
      i = i + 1
    }
    let mut val = ""
    if i < n && chars[i] == '"' {
      let (v, ni) = scan_quoted(chars, i, n)
      val = v
      i = ni
      // Tolerate padding before the next ';'.
      while i < n && chars[i] != ';' {
        i = i + 1
      }
    } else {
      let valbuf = StringBuilder()
      while i < n && chars[i] != ';' {
        valbuf.write_char(chars[i])
        i = i + 1
      }
      val = valbuf.to_string().trim().to_owned()
    }
    params.push((key, val))
  }
  (token, params)
}

///|
/// Read a quoted-string starting at chars[start] == '"'. Returns the
/// unquoted value and the index just past the closing quote.
fn scan_quoted(
  chars : Array[Char],
  start : Int,
  n : Int,
) -> (String, Int) raise {
  let buf = StringBuilder()
  let mut i = start + 1
  let mut closed = false
  while i < n {
    let c = chars[i]
    if c == '\\' && i + 1 < n {
      buf.write_char(chars[i + 1])
      i = i + 2
    } else if c == '"' {
      i = i + 1
      closed = true
      break
    } else {
      buf.write_char(c)
      i = i + 1
    }
  }
  guard closed else {
    raise @error.PgpError::PgpError(msg="mime: unterminated quoted string")
  }
  (buf.to_string(), i)
}

///|
/// Parse a Content-Type header value. Raises on structurally invalid
/// values (no type/subtype or a parameter without a value).
pub fn parse_content_type(value : String) -> MediaType raise {
  let (token, params) = parse_header_params(value)
  guard token.contains("/") else {
    raise @error.PgpError::PgpError(
      msg="mime: invalid content type \"\{token}\"",
    )
  }
  let slash = match token.find("/") {
    Some(k) => k
    None => 0
  }
  let main_type = token[0:slash].to_owned()
  let sub_type = token[slash + 1:token.length()].to_owned()
  guard main_type != "" && sub_type != "" else {
    raise @error.PgpError::PgpError(
      msg="mime: invalid content type \"\{token}\"",
    )
  }
  MediaType::{ main_type, sub_type, params, }
}
