///|
/// Message entity builders. Byte rules follow the P1 PGP/MIME
/// conventions (see HANDOFF): everything CRLF, the CRLF preceding a
/// boundary belongs to the boundary, and signed entities carry exactly
/// one trailing CRLF (mime_canonicalize re-adds it on verification).

///|
/// An RFC 5322 attachment leaf: base64 CTE, Content-Disposition:
/// attachment.
pub(all) struct MailAttachment {
  filename : String
  content_type : String
  data : Bytes
} derive(Debug)

///|
fn new_boundary() -> String raise {
  "mp_" + @primitives.to_hex(@primitives.random_bytes(12)) + "_mp"
}

///|
fn normalize_crlf(s : String) -> String {
  s.replace_all(old="\r\n", new="\n").replace_all(old="\n", new="\r\n")
}

///|
/// 7bit-eligible per RFC 3156 §3: printable ASCII plus TAB and CRLF
/// pairs only — a bare CR or LF would violate the SMTP wire format
/// (RFC 5321 §2.3.8), so such text must go through the QP path.
fn is_ascii_text(s : String) -> Bool {
  let mut prev_cr = false
  for c in s {
    let v = c.to_int()
    if prev_cr && v != 10 {
      return false
    }
    prev_cr = v == 13
    if !(v == 9 || v == 10 || v == 13 || (v >= 32 && v <= 126)) {
      return false
    }
  }
  !prev_cr
}

///|
fn escape_quoted(s : String) -> String {
  let sb = StringBuilder()
  for c in s {
    if c == '"' || c == '\\' {
      sb.write_char('\\')
    }
    sb.write_char(c)
  }
  sb.to_string()
}

///|
/// base64 with 76-char CRLF lines (RFC 2045 §6.8).
fn b64_wrapped(data : BytesView) -> String {
  let b64 = @base64.encode(data)
  let sb = StringBuilder()
  let n = b64.length()
  let mut i = 0
  while i < n {
    let end = if i + 76 < n { i + 76 } else { n }
    sb.write_stringview(b64[i:end])
    sb.write_string("\r\n")
    i = end
  }
  sb.to_string()
}

///|
/// multipart/mixed: text/plain body (7bit when pure ASCII per the
/// RFC 3156 §3 constraint, quoted-printable otherwise) plus base64
/// attachments.
pub fn build_multipart_mixed(
  text : String,
  attachments : Array[MailAttachment],
) -> String raise {
  let boundary = new_boundary()
  let normalized = normalize_crlf(text)
  let (cte, body) = if is_ascii_text(normalized) {
    ("7bit", normalized)
  } else {
    (
      "quoted-printable",
      bytes_to_ascii(
        encode_quoted_printable(@primitives.utf8_bytes(normalized).exact_view()),
      ),
    )
  }
  let sb = StringBuilder()
  sb.write_string(
    "Content-Type: multipart/mixed; boundary=\"\{boundary}\"\r\n\r\n",
  )
  sb.write_string("--\{boundary}\r\n")
  sb.write_string("Content-Type: text/plain; charset=utf-8\r\n")
  sb.write_string("Content-Transfer-Encoding: \{cte}\r\n\r\n")
  sb.write_string(body)
  if !body.has_suffix("\r\n") {
    sb.write_string("\r\n")
  }
  for att in attachments {
    require_ascii(att.filename, "attachment filename")
    require_ascii(att.content_type, "attachment content type")
    let ct = if att.content_type == "" {
      "application/octet-stream"
    } else {
      att.content_type
    }
    sb.write_string("--\{boundary}\r\n")
    sb.write_string("Content-Type: \{ct}\r\n")
    sb.write_string("Content-Transfer-Encoding: base64\r\n")
    sb.write_string(
      "Content-Disposition: attachment; filename=\"\{escape_quoted(att.filename)}\"\r\n\r\n",
    )
    sb.write_string(b64_wrapped(att.data.exact_view()))
  }
  sb.write_string("--\{boundary}--\r\n")
  sb.to_string()
}

///|
/// Generalization of mime.build_pgp_mime_signed: detached-sign a
/// PRE-BUILT entity and wrap it as multipart/signed. The signature
/// covers the entity bytes plus exactly one trailing CRLF — which is
/// the CRLF preceding the signature boundary on the wire, so
/// mime_canonicalize reconstructs the signed input verbatim (GnuPG and
/// Proton shapes alike; verified against gpg 2.4.5).
pub fn build_pgp_mime_signed_entity(
  entity : String,
  key : @api.PrivateKey,
) -> String raise {
  let boundary = new_boundary()
  let mut ent = normalize_crlf(entity)
  if !ent.has_suffix("\r\n") {
    ent = ent + "\r\n"
  }
  let sig = @api.sign_detached(@primitives.utf8_bytes(ent).exact_view(), key)
  let sb = StringBuilder()
  sb.write_string(
    "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"\{boundary}\"\r\n\r\n",
  )
  sb.write_string("--\{boundary}\r\n")
  sb.write_string(ent)
  sb.write_string("--\{boundary}\r\n")
  sb.write_string(
    "Content-Type: application/pgp-signature; name=\"OpenPGP_signature.asc\"\r\n",
  )
  sb.write_string(
    "Content-Disposition: attachment; filename=\"OpenPGP_signature.asc\"\r\n\r\n",
  )
  sb.write_string(sig)
  if !sig.has_suffix("\n") {
    sb.write_string("\n")
  }
  sb.write_string("\r\n--\{boundary}--\r\n")
  sb.to_string()
}

///|
/// One-shot encrypted+signed mail (RFC 3156 §6.1 encapsulation, sign
/// then encrypt):
///   headers (From/To/Subject/Date/Message-ID)
///   multipart/encrypted
///     └─ armored PGP MESSAGE
///         └─ multipart/signed
///             └─ multipart/mixed (text + attachments)
/// Subject and display names are RFC 2047 encoded automatically
/// (=?utf-8?B?...?=); addr-specs and domains stay ASCII (EAI/SMTPUTF8 is
/// out of scope). The entity headers (MIME-Version/Content-Type) continue
/// the same header block, so no extra blank line is inserted.
pub fn build_encrypted_mail(
  from : MailAddress,
  to : Array[MailAddress],
  subject~ : String,
  text~ : String,
  attachments~ : Array[MailAttachment],
  signer~ : @api.PrivateKey,
  recipients~ : Array[@api.PublicKey],
  domain~ : String,
  now_unix? : Int64,
  tz_offset_minutes? : Int,
) -> String raise {
  guard !to.is_empty() else {
    raise @error.PgpError::PgpError(msg="mail: no To addresses")
  }
  guard !recipients.is_empty() else {
    raise @error.PgpError::PgpError(msg="mail: no encryption recipients")
  }
  let subject = encode_rfc2047(subject)
  let now = now_unix.unwrap_or(@primitives.unix_now())
  let tz = match tz_offset_minutes {
    Some(t) => t
    None => local_tz_offset_minutes(now)
  }
  let mut to_line = ""
  for i, a in to {
    if i > 0 {
      to_line = to_line + ", "
    }
    to_line = to_line + format_address(a)
  }
  let mid = message_id(@primitives.random_bytes(16), domain)
  let sb = StringBuilder()
  sb.write_string("From: \{format_address(from)}\r\n")
  sb.write_string("To: \{to_line}\r\n")
  sb.write_string("Subject: \{subject}\r\n")
  sb.write_string("Date: \{rfc5322_date(now, tz)}\r\n")
  sb.write_string("Message-ID: \{mid}\r\n")
  let mixed = build_multipart_mixed(text, attachments)
  let signed = build_pgp_mime_signed_entity(mixed, signer)
  let armored = @api.encrypt_to_recipients(
    @primitives.utf8_bytes(signed).exact_view(),
    recipients,
  )
  sb.write_string(@mime.build_pgp_mime_encrypted(armored))
  sb.to_string()
}

///|
pub extend MailAttachment with @moonbitlang/core/debug.Debug::{to_repr}
