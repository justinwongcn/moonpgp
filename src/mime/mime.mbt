///|
/// Minimal RFC 2045/RFC 3156 support for PGP/MIME mail: building
/// multipart/encrypted and multipart/signed messages and extracting the
/// OpenPGP payloads from received ones.

///|
/// A parsed MIME message: top-level headers and the raw body.
pub struct MimeMessage {
  headers : Array[(String, String)]
  body : String
} derive(Debug)

///|
pub fn MimeMessage::header(self : MimeMessage, name : String) -> String? {
  let lower = name.to_lower()
  for pair in self.headers {
    if pair.0.to_lower() == lower {
      return Some(pair.1)
    }
  }
  None
}

///|
/// Parse a header block + body. Headers are terminated by the first empty
/// line; folded (continuation) headers are joined.
pub fn parse_message(text : String) -> MimeMessage {
  let normalized = text.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let headers = parse_folded_headers(lines)
  // Skip past the first empty line separating headers from the body.
  let mut i = 0
  while i < lines.length() && lines[i] != "" {
    i = i + 1
  }
  if i < lines.length() {
    i = i + 1
  }
  let body = StringBuilder()
  while i < lines.length() {
    body.write_stringview(lines[i])
    body.write_char('\n')
    i = i + 1
  }
  MimeMessage::{ headers, body: body.to_string(), }
}

///|
/// Extract the `boundary` parameter of a Content-Type header value.
pub fn content_type_boundary(content_type : String) -> String? {
  let lower = content_type.to_lower()
  guard lower.contains("boundary=") else { return None }
  let idx = match lower.find("boundary=") {
    Some(i) => i + "boundary=".length()
    None => return None
  }
  let rest = content_type[idx:content_type.length()]
  let rest = if rest.has_prefix("\"") {
    match rest[1:rest.length()].find("\"") {
      Some(end) => rest[1:1 + end].to_owned()
      None => rest[1:rest.length()].to_owned()
    }
  } else {
    match rest.find(";") {
      Some(end) => rest[0:end].to_owned()
      None => rest.to_owned()
    }
  }
  Some(rest)
}

///|
/// Split a multipart body into raw parts (each part includes its headers
/// and body exactly as transmitted, minus the boundary delimiters).
pub fn split_multipart(body : String, boundary : String) -> Array[String] raise {
  let dash_boundary = "--" + boundary
  let normalized = body.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let parts : Array[String] = []
  let mut current : Array[StringView]? = None
  for line in lines {
    let is_delimiter = line == dash_boundary ||
      line.has_prefix(dash_boundary + "--")
    if is_delimiter {
      match current {
        Some(c) => parts.push(join_lines(c))
        None => ()
      }
      if line.has_prefix(dash_boundary + "--") {
        current = None
      } else {
        current = Some([])
      }
    } else {
      match current {
        Some(c) => c.push(line)
        None => ()
      }
    }
  }
  guard parts.length() > 0 else {
    raise @error.PgpError::PgpError(msg="mime: no multipart parts found")
  }
  parts
}

///|
fn join_lines(lines : Array[StringView]) -> String {
  let buf = StringBuilder()
  for i in 0..<lines.length() {
    buf.write_stringview(lines[i])
    if i < lines.length() - 1 {
      buf.write_char('\n')
    }
  }
  buf.to_string()
}

///|
fn random_boundary() -> String raise {
  let raw = @primitives.random_bytes(12)
  "=" + @primitives.to_hex(raw) + "=moonpgp="
}

///|
/// Extract the armored OpenPGP message from a received
/// multipart/encrypted body (RFC 3156 §6). Returns the PGP MESSAGE armor.
pub fn extract_pgp_encrypted(mime_text : String) -> String raise {
  let msg = parse_message(mime_text)
  let content_type = match msg.header("Content-Type") {
    Some(ct) => ct
    None => raise @error.PgpError::PgpError(msg="mime: missing Content-Type")
  }
  guard content_type.to_lower().contains("multipart/encrypted") else {
    raise @error.PgpError::PgpError(msg="mime: not multipart/encrypted")
  }
  let boundary = match content_type_boundary(content_type) {
    Some(b) => b
    None => raise @error.PgpError::PgpError(msg="mime: missing boundary")
  }
  let parts = split_multipart(msg.body, boundary)
  guard parts.length() >= 2 else {
    raise @error.PgpError::PgpError(
      msg="mime: multipart/encrypted needs 2 parts",
    )
  }
  let body = strip_leading_headers_keep_body(parts[1])
  if body.has_suffix("\n") {
    body
  } else {
    body + "\n"
  }
}

///|
/// The signature half of a received multipart/signed message: the exact
/// raw bytes of the signed part and the armored signature.
pub(all) struct PgpMimeSigned {
  signed_bytes : Bytes
  signature_armor : String
} derive(Debug)

///|
/// Extract (and later verify) a received multipart/signed message
/// (RFC 3156 §5).
pub fn extract_pgp_signed(mime_text : String) -> PgpMimeSigned raise {
  let msg = parse_message(mime_text)
  let content_type = match msg.header("Content-Type") {
    Some(ct) => ct
    None => raise @error.PgpError::PgpError(msg="mime: missing Content-Type")
  }
  guard content_type.to_lower().contains("multipart/signed") else {
    raise @error.PgpError::PgpError(msg="mime: not multipart/signed")
  }
  let boundary = match content_type_boundary(content_type) {
    Some(b) => b
    None => raise @error.PgpError::PgpError(msg="mime: missing boundary")
  }
  let parts = split_multipart(msg.body, boundary)
  guard parts.length() >= 2 else {
    raise @error.PgpError::PgpError(msg="mime: multipart/signed needs 2 parts")
  }
  // The signature part's body (after its blank line) is the armor.
  let sig_part = parse_message(parts[1])
  let sig_armor = strip_leading_headers_keep_body(parts[1])
  ignore(sig_part)
  // The signed content: the raw first part, re-encoded to CRLF exactly as
  // transmitted. Per the RFC 3156 convention the signed data ends with a
  // CRLF; the split dropped it as boundary-attached, so restore it.
  let signed_raw = parts[0].replace_all(old="\n", new="\r\n") + "\r\n"
  PgpMimeSigned::{
    signed_bytes: @primitives.utf8_bytes(signed_raw),
    signature_armor: sig_armor,
  }
}

///|
/// Drop the part's MIME headers (up to the first blank line) and keep the
/// body as-is.
fn strip_leading_headers_keep_body(part : String) -> String {
  let normalized = part.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let mut i = 0
  while i < lines.length() && lines[i] != "" {
    i = i + 1
  }
  // Skip the blank line itself.
  if i < lines.length() {
    i = i + 1
  }
  let buf = StringBuilder()
  while i < lines.length() {
    buf.write_stringview(lines[i])
    if i < lines.length() - 1 {
      buf.write_char('\n')
    }
    i = i + 1
  }
  buf.to_string()
}

///|
/// Build a multipart/encrypted PGP/MIME message around an armored PGP
/// MESSAGE (RFC 3156 §6).
pub fn build_pgp_mime_encrypted(armored_message : String) -> String raise {
  let boundary = random_boundary()
  let buf = StringBuilder()
  buf.write_string("MIME-Version: 1.0\r\n")
  buf.write_string(
    "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"\{boundary}\"\r\n\r\n",
  )
  buf.write_string("--\{boundary}\r\n")
  buf.write_string("Content-Type: application/pgp-encrypted\r\n\r\n")
  buf.write_string("Version: 1\r\n\r\n")
  buf.write_string("--\{boundary}\r\n")
  buf.write_string("Content-Type: application/octet-stream\r\n\r\n")
  buf.write_string(armored_message)
  if !armored_message.has_suffix("\n") {
    buf.write_char('\n')
  }

  buf.write_string("--\{boundary}--\r\n")
  buf.to_string()
}

///|
/// Build a multipart/signed PGP/MIME message over UTF-8 text with the
/// SHA-256 signature of `key` (RFC 3156 §5). The first part is signed over
/// its exact transmitted bytes (CRLF line endings).
pub fn build_pgp_mime_signed(
  text : String,
  key : @api.PrivateKey,
) -> String raise {
  let boundary = random_boundary()
  // Part 1: text/plain. Assemble with bare LF, then convert to CRLF once
  // so the body's own line endings are not doubled.
  let body_lf = text.replace_all(old="\r\n", new="\n")
  let part1_lf = "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n\{body_lf}"
  if !part1_lf.has_suffix("\n") {
    ignore(part1_lf)
  }
  let part1 = part1_lf.replace_all(old="\n", new="\r\n")
  let signed_bytes = @primitives.utf8_bytes(part1)
  let sig_armor = @api.sign_detached(signed_bytes.exact_view(), key)
  let buf = StringBuilder()
  buf.write_string("MIME-Version: 1.0\r\n")
  buf.write_string(
    "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"\{boundary}\"\r\n\r\n",
  )
  buf.write_string("--\{boundary}\r\n")
  buf.write_string(part1)
  if !part1.has_suffix("\r\n") {
    buf.write_string("\r\n")
  }
  buf.write_string("--\{boundary}\r\n")
  buf.write_string(
    "Content-Type: application/pgp-signature; name=\"OpenPGP_signature.asc\"\r\nContent-Disposition: attachment; filename=\"OpenPGP_signature.asc\"\r\n\r\n",
  )
  buf.write_string(sig_armor)
  if !sig_armor.has_suffix("\n") {
    buf.write_char('\n')
  }
  // The boundary delimiter line requires a preceding CRLF of its own.
  buf.write_string("\r\n")
  buf.write_string("--\{boundary}--\r\n")
  buf.to_string()
}

///|
/// Convenience: verify a received multipart/signed message against
/// `verifier`; returns the signed text and the status.
pub fn verify_pgp_mime_signed(
  mime_text : String,
  verifier : @api.PublicKey,
) -> (String, @api.VerifyStatus) raise {
  let signed = extract_pgp_signed(mime_text)
  let status = @api.verify_detached(
    signed.signed_bytes.exact_view(),
    signed.signature_armor,
    verifier,
  )
  let text = @utf8.decode(signed.signed_bytes.exact_view()) catch { _ => "" }
  (text, status)
}

///|
pub extend MimeMessage with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PgpMimeSigned with @moonbitlang/core/debug.Debug::{to_repr}
