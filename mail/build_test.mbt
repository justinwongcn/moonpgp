///|
/// Callback recorder for the compose→decrypt roundtrip test.
struct BuildRecorder {
  bodies : Array[(String, String)]
  attachments : Array[(String, Bytes)]
  verified : Array[@api.VerifyStatus]
  errors : Array[String]
}

///|
impl @mime.MimeCallbacks for BuildRecorder with fn on_body(self, body, mimetype) {
  self.bodies.push((body, mimetype))
}

///|
impl @mime.MimeCallbacks for BuildRecorder with fn on_attachment(
  self,
  headers,
  data,
) {
  let mut name = "?"
  for pair in headers {
    if pair.0.to_lower() == "content-disposition" {
      name = pair.1
    }
  }
  self.attachments.push((name, data))
}

///|
impl @mime.MimeCallbacks for BuildRecorder with fn on_verified(self, status) {
  self.verified.push(status)
}

///|
impl @mime.MimeCallbacks for BuildRecorder with fn on_error(self, message) {
  self.errors.push(message)
}

///|
test "multipart/mixed: ascii body is 7bit, structure intact" {
  let out = @mail.build_multipart_mixed("plain ascii body\n", [])
  assert_true(out.contains("Content-Transfer-Encoding: 7bit"))
  assert_true(out.contains("Content-Type: multipart/mixed; boundary=\"mp_"))
  assert_true(out.has_suffix("--\r\n"))
}

///|
test "multipart/mixed: non-ascii body switches to quoted-printable" {
  let out = @mail.build_multipart_mixed("café body\n", [])
  assert_true(out.contains("Content-Transfer-Encoding: quoted-printable"))
  assert_true(out.contains("caf=C3=A9"))
}

///|
test "multipart/mixed: attachments are base64 with disposition" {
  let att : @mail.MailAttachment = {
    filename: "data.bin",
    content_type: "application/octet-stream",
    data: @primitives.utf8_bytes("ATTACHMENT-PAYLOAD"),
  }
  let out = @mail.build_multipart_mixed("body\n", [att])
  assert_true(
    out.contains("Content-Disposition: attachment; filename=\"data.bin\""),
  )
  assert_true(out.contains("Content-Transfer-Encoding: base64"))
  // the base64 payload must decode back to the original bytes
  let payload = "QVRUQUNITUVOVC1QQVlMT0FE" // base64("ATTACHMENT-PAYLOAD")
  assert_true(out.contains(payload))
}

///|
test "signed entity: verifies and round-trips the exact bytes" {
  let key = @api.generate_key("Mail Build <mb@example.com>", bits=1024)
  let entity = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nsigned entity body\r\n"
  let signed = @mail.build_pgp_mime_signed_entity(entity, key)
  let extracted = @mime.extract_pgp_signed(signed)
  assert_eq(extracted.signed_bytes, @primitives.utf8_bytes(entity))
  let status = @api.verify_detached(
    extracted.signed_bytes.exact_view(),
    extracted.signature_armor,
    key.to_public(),
  )
  assert_eq(status, @api.Ok)
}

///|
test "encrypted mail: one-shot compose then decrypt_mime roundtrip" {
  let key = @api.generate_key("Mail Build <mb@example.com>", bits=1024)
  let att : @mail.MailAttachment = {
    filename: "note.txt",
    content_type: "text/plain",
    data: @primitives.utf8_bytes("attachment body"),
  }
  let message = @mail.build_encrypted_mail(
    { display_name: "Alice", addr: "alice@example.com", },
    [{ display_name: "Bob", addr: "bob@example.com", }],
    subject="quarterly report",
    text="hello bob\nsecond line\n",
    attachments=[att],
    signer=key,
    recipients=[key.to_public()],
    domain="mailpgp.example",
    now_unix=1790906400L,
    tz_offset_minutes=480,
  )
  // RFC 5322 headers present
  assert_true(
    message.has_prefix(
      "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\n",
    ),
  )
  assert_true(message.contains("Subject: quarterly report\r\n"))
  assert_true(message.contains("Date: Fri, 02 Oct 2026 10:00:00 +0800\r\n"))
  assert_true(message.contains("Message-ID: <"))
  // full pipeline: decrypt, walk, verify, collect
  let cb = BuildRecorder::{
    bodies: [],
    attachments: [],
    verified: [],
    errors: [],
  }
  @mime.decrypt_mime(message, [key], verifiers=[key.to_public()], callbacks=cb)
  assert_eq(cb.errors, [])
  assert_eq(cb.verified, [@api.Ok])
  // The parser delivers the body as transmitted: composed text is
  // CRLF-normalized on assembly, and the CRLF before the boundary
  // belongs to the boundary (RFC 2046) — so the trailing newline is
  // not part of the delivered body. Same asymmetry as gopenpgp.
  assert_eq(cb.bodies, [("hello bob\r\nsecond line", "text/plain")])
  assert_eq(cb.attachments.length(), 1)
  assert_eq(cb.attachments[0].1, @primitives.utf8_bytes("attachment body"))
}

///|
test "encrypted mail: non-ascii subject is RFC 2047 encoded" {
  let key = @api.generate_key("Mail Build <mb@example.com>", bits=1024)
  let mail_text = @mail.build_encrypted_mail(
    { display_name: "", addr: "a@b.example", },
    [{ display_name: "", addr: "c@d.example", }],
    subject="中文主题",
    text="x",
    attachments=[],
    signer=key,
    recipients=[key.to_public()],
    domain="x.example",
  )
  assert_true(mail_text.contains("Subject: =?utf-8?B?"))
  // And a CR/LF-injecting subject still fails fast.
  let raised = try {
    ignore(
      @mail.build_encrypted_mail(
        { display_name: "", addr: "a@b.example", },
        [{ display_name: "", addr: "c@d.example", }],
        subject="x\r\nBcc: evil@example.com",
        text="x",
        attachments=[],
        signer=key,
        recipients=[key.to_public()],
        domain="x.example",
      ),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
