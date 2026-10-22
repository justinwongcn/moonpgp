///|
let max_mime_depth : Int32 = 20

///|
/// One node of the MIME tree. `raw` holds the exact transmitted bytes of
/// the whole part (headers + blank line + body, original line endings) —
/// multipart/signed signatures cover headers plus body (RFC 1847), so
/// the raw span must survive parsing untouched. `body_raw` is the body as
/// transmitted; `body` is transfer-decoded. Parsing is byte-level: binary
/// leaves survive without any String round trip.
pub struct MimePart {
  headers : Array[(String, String)]
  content_type : MediaType
  raw : Bytes
  body_raw : Bytes
  body : Bytes
  parts : Array[MimePart]
} derive(Debug)

///|
/// Case-insensitive header lookup; the first occurrence wins (unlike
/// `MediaType::param`, where later duplicates override earlier ones).
pub fn MimePart::header(self : MimePart, name : String) -> String? {
  header_lookup(self.headers, name)
}

///|
pub fn MimePart::is_multipart(self : MimePart) -> Bool {
  self.content_type.main_type == "multipart"
}

///|
/// Parse a full MIME message (or one part) into a tree.
pub fn parse_mime_tree(data : Bytes) -> MimePart raise {
  parse_part(data.exact_view(), 0)
}

///|
fn parse_part(data : BytesView, depth : Int32) -> MimePart raise {
  guard depth <= max_mime_depth else { @error.fail("mime: nesting too deep") }
  let (header_end, body_start) = split_headers_body(data)
  let header_text = @utf8.decode_lossy(data[0:header_end])
  let headers = parse_header_block(header_text)
  // A structurally invalid Content-Type degrades this part to the
  // text/plain default instead of failing the whole tree (gomime ignores
  // ParseMediaType errors the same way).
  let content_type = match header_lookup(headers, "Content-Type") {
    Some(v) => parse_content_type(v) catch { _ => default_media_type() }
    None => default_media_type()
  }
  let body_raw = data[body_start:data.length()].to_owned()
  let cte = header_lookup(headers, "Content-Transfer-Encoding")
  // A failing base64 body degrades to empty content for this part only,
  // like gomime's decodePart; the rest of the message is unaffected.
  let body = decode_transfer_encoding(body_raw.exact_view(), cte) catch {
    _ => Bytes::from_array([])
  }
  let parts : Array[MimePart] = []
  if content_type.main_type == "multipart" {
    match content_type.param("boundary") {
      // An empty boundary would degenerate the delimiter to "--".
      Some(boundary) if boundary != "" =>
        for child in split_multipart_bytes(body_raw.exact_view(), boundary) {
          parts.push(parse_part(child, depth + 1))
        }
      _ => @error.fail("mime: multipart without boundary")
    }
  }
  MimePart::{
    headers,
    content_type,
    raw: data.to_owned(),
    body_raw,
    body,
    parts,
  }
}

///|
fn header_lookup(headers : Array[(String, String)], name : String) -> String? {
  let lower = name.to_lower()
  for pair in headers {
    if pair.0.to_lower() == lower {
      return Some(pair.1)
    }
  }
  None
}

///|
/// Next line in [pos, length): (content_start, content_end, next_pos).
/// Content excludes the CRLF/LF terminator; next_pos points past it
/// (== length at EOF). A lone CR at EOF stays in the content.
fn next_line(data : BytesView, pos : Int32) -> (Int32, Int32, Int32)? {
  let n = data.length()
  if pos >= n {
    return None
  }
  let mut i = pos
  while i < n && data[i] != b'\n' {
    i = i + 1
  }
  let mut end = i
  let next = if i < n { i + 1 } else { n }
  // Strip the CR only when the line is actually LF-terminated; a lone CR
  // at EOF stays in the content.
  if i < n && end > pos && data[end - 1] == b'\r' {
    end = end - 1
  }
  Some((pos, end, next))
}

///|
/// Split a part span into (header_block_end, body_start): the header
/// block runs to before the first empty line, body starts past its
/// terminator. Header-only parts get (length, length).
fn split_headers_body(data : BytesView) -> (Int32, Int32) {
  let n = data.length()
  let mut pos = 0
  let mut done = false
  let mut result = (n, n)
  while !done {
    match next_line(data, pos) {
      None => done = true
      Some((cs, ce, np)) =>
        if ce == cs {
          result = (cs, np)
          done = true
        } else {
          pos = np
        }
    }
  }
  result
}

///|
/// Parse folded header lines (RFC 5322 §2.2.3) up to the first empty
/// line. Shared with `MimeMessage::parse_message`.
fn parse_folded_headers(lines : Array[StringView]) -> Array[(String, String)] {
  let headers : Array[(String, String)] = []
  let mut current_name = ""
  let current_value = StringBuilder()
  for line in lines {
    if line == "" {
      break
    }
    if (line.has_prefix(" ") || line.has_prefix("\t")) && current_name != "" {
      current_value.write_char(' ')
      current_value.write_stringview(line.trim())
    } else {
      if current_name != "" {
        headers.push((current_name, current_value.to_string()))
      }
      match line.split_once(":") {
        Some((k, v)) => {
          current_name = k.to_owned()
          current_value.reset()
          current_value.write_stringview(v.trim())
        }
        None => {
          current_name = ""
          current_value.reset()
        }
      }
    }
  }
  if current_name != "" {
    headers.push((current_name, current_value.to_string()))
  }
  headers
}

///|
/// Parse folded header lines out of a header block.
fn parse_header_block(text : String) -> Array[(String, String)] {
  let normalized = text.replace_all(old="\r\n", new="\n")
  parse_folded_headers(normalized.split("\n").collect())
}

///|
fn starts_with_at(
  data : BytesView,
  start : Int32,
  end : Int32,
  prefix : BytesView,
) -> Bool {
  let plen = prefix.length()
  if end - start < plen {
    return false
  }
  for k in 0..<plen {
    if data[start + k] != prefix[k] {
      return false
    }
  }
  true
}

///|
fn rest_is_padding(data : BytesView, start : Int32, end : Int32) -> Bool {
  for k in start..<end {
    let b = data[k].to_int()
    if b != 32 && b != 9 {
      return false
    }
  }
  true
}

///|
fn line_is_delim(
  body : BytesView,
  cs : Int32,
  ce : Int32,
  dash : BytesView,
) -> Bool {
  starts_with_at(body, cs, ce, dash) &&
  rest_is_padding(body, cs + dash.length(), ce)
}

///|
fn line_is_close(
  body : BytesView,
  cs : Int32,
  ce : Int32,
  dash : BytesView,
) -> Bool {
  let dl = dash.length()
  if ce - cs < dl + 2 || !starts_with_at(body, cs, ce, dash) {
    return false
  }
  if body[cs + dl] != b'-' || body[cs + dl + 1] != b'-' {
    return false
  }
  rest_is_padding(body, cs + dl + 2, ce)
}

///|
/// Child span for a part opened at `start` and closed by the boundary
/// line starting at `boundary_line_start`: ends right before the line
/// terminator that belongs to the boundary (RFC 2046 §5.1.1).
fn child_span(
  body : BytesView,
  start : Int32,
  boundary_line_start : Int32,
) -> BytesView {
  let mut end = boundary_line_start
  if end > start && body[end - 1] == b'\n' {
    end = end - 1
    if end > start && body[end - 1] == b'\r' {
      end = end - 1
    }
  }
  body[start:end]
}

///|
/// Split a multipart body into the raw byte spans of its child parts,
/// each span = headers + blank line + body exactly as transmitted (the
/// bytes multipart/signed must verify over). A missing close delimiter
/// is tolerated; the epilogue after it is ignored.
fn split_multipart_bytes(
  body : BytesView,
  boundary : String,
) -> Array[BytesView] raise {
  let dash = @primitives.utf8_bytes("--" + boundary).exact_view()
  let n = body.length()
  let parts : Array[BytesView] = []
  let mut pos = 0
  let mut child_start : Int32? = None
  let mut finished = false
  while !finished {
    match next_line(body, pos) {
      None => finished = true
      Some((cs, ce, np)) => {
        if line_is_close(body, cs, ce, dash) {
          match child_start {
            Some(s) => {
              parts.push(child_span(body, s, cs))
              child_start = None
            }
            None => ()
          }
          finished = true
        } else if line_is_delim(body, cs, ce, dash) {
          match child_start {
            Some(s) => {
              parts.push(child_span(body, s, cs))
              child_start = Some(np)
            }
            None => child_start = Some(np)
          }
        }
        pos = np
      }
    }
  }
  match child_start {
    Some(s) => parts.push(body[s:n])
    None => ()
  }
  guard parts.length() > 0 else {
    @error.fail("mime: no multipart parts found")
  }
  parts
}

///|
/// Body handed to OnBody: content plus its exact mimetype.
pub(all) struct MimeBody {
  content : Bytes
  mimetype : String
} derive(Debug)

///|
/// One attachment handed to OnAttachment.
pub(all) struct MimeAttachment {
  headers : Array[(String, String)]
  data : Bytes
  filename : String?
  mimetype : String
} derive(Debug)

///|
priv struct MimeCollector {
  html : Array[Bytes]
  plain : Array[Bytes]
  attachments : Array[MimeAttachment]
}

///|
fn collect_leaf(part : MimePart, c : MimeCollector) -> Unit {
  let mut disposition = ""
  let mut filename : String? = None
  match part.header("Content-Disposition") {
    Some(v) => {
      let (token, ps) = parse_header_params(v) catch { _ => ("", []) }
      disposition = token
      filename = param_of(ps, "filename")
    }
    None => ()
  }
  if filename is None {
    filename = part.content_type.param("name")
  }
  // gomime semantics: only text/html and text/plain leaves buffer into
  // the body (html wins over plain regardless of order); any other leaf
  // type — and anything with an `attachment` disposition — becomes an
  // attachment.
  let mimetype = part.content_type.mimetype()
  let is_body = disposition != "attachment" &&
    (mimetype == "text/html" || mimetype == "text/plain")
  if !is_body {
    c.attachments.push(MimeAttachment::{
      headers: part.headers,
      data: part.body,
      filename,
      mimetype,
    })
  } else if mimetype == "text/html" {
    c.html.push(part.body)
  } else {
    c.plain.push(part.body)
  }
}

///|
fn collect_walk(part : MimePart, c : MimeCollector) -> Unit {
  if part.is_multipart() {
    for child in part.parts {
      collect_walk(child, c)
    }
    return
  }
  collect_leaf(part, c)
}

///|
fn concat_bytes(chunks : Array[Bytes]) -> Bytes {
  let out : Array[Byte] = []
  for b in chunks {
    for byte in b {
      out.push(byte)
    }
  }
  Bytes::from_array(out)
}

///|
/// Classify the leaves of the tree the way gopenpgp's gomime collector
/// chain does: html/plain leaves buffer into the body (html wins),
/// everything else — including other text/* types and anything with an
/// `attachment` disposition — becomes an attachment. The body is None
/// only when the tree contains no text/html/plain leaf at all.
pub fn collect_body_and_attachments(
  root : MimePart,
) -> (MimeBody?, Array[MimeAttachment]) {
  let c = MimeCollector::{ html: [], plain: [], attachments: [], }
  collect_walk(root, c)
  if !c.html.is_empty() {
    (
      Some(MimeBody::{ content: concat_bytes(c.html), mimetype: "text/html", }),
      c.attachments,
    )
  } else if !c.plain.is_empty() {
    (
      Some(MimeBody::{ content: concat_bytes(c.plain), mimetype: "text/plain", }),
      c.attachments,
    )
  } else {
    (None, c.attachments)
  }
}

///|
pub extend MimeAttachment with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend MimeBody with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend MimePart with @moonbitlang/core/debug.Debug::{to_repr}
