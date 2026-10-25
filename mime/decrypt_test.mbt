///|
/// Callback recorder shared by the @mime.decrypt_mime tests.
struct CollectCallbacks {
  bodies : Array[(String, String)]
  attachments : Array[(Array[(String, String)], Bytes)]
  verified : Array[@api.VerifyStatus]
  errors : Array[String]
}

///|
fn new_callbacks() -> CollectCallbacks {
  CollectCallbacks::{ bodies: [], attachments: [], verified: [], errors: [], }
}

///|
impl @mime.MimeCallbacks for CollectCallbacks with fn on_body(
  self,
  body,
  mimetype,
) {
  self.bodies.push((body, mimetype))
}

///|
impl @mime.MimeCallbacks for CollectCallbacks with fn on_attachment(
  self,
  headers,
  data,
) {
  self.attachments.push((headers, data))
}

///|
impl @mime.MimeCallbacks for CollectCallbacks with fn on_verified(self, status) {
  self.verified.push(status)
}

///|
impl @mime.MimeCallbacks for CollectCallbacks with fn on_error(self, message) {
  self.errors.push(message)
}

///|
test "@mime.decrypt_mime: signed then encrypted roundtrip" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let inner = @mime.build_pgp_mime_signed("mime body\nsecond line\n", key)
  let armored = @api.encrypt_to_recipients(@primitives.utf8_bytes(inner), [
    key.to_public(),
  ])
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  assert_eq(cb.errors.length(), 0)
  assert_eq(cb.verified, [@api.Ok])
  assert_eq(cb.bodies.length(), 1)
  assert_true(cb.bodies[0].0.contains("mime body"))
  assert_eq(cb.bodies[0].1, "text/plain")
}

///|
test "@mime.decrypt_mime: tampered inner signature fails and still delivers" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let signed = @mime.build_pgp_mime_signed("authentic body\n", key)
  let tampered = signed.replace(old="authentic", new="tampered body")
  let armored = @api.encrypt_to_recipients(@primitives.utf8_bytes(tampered), [
    key.to_public(),
  ])
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  // Embedded side unsigned (NotSigned), MIME side Failed: both errors
  // surface and the worse status wins (gopenpgp scenario_13 shape).
  assert_eq(cb.errors.length(), 2)
  assert_eq(cb.verified, [@api.Failed])
  assert_eq(cb.bodies.length(), 1)
  assert_true(cb.bodies[0].0.contains("tampered body"))
}

///|
test "@mime.decrypt_mime: unsigned payload with verifiers reports NotSigned" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let armored = @api.encrypt_to_recipients(
    @primitives.utf8_bytes(
      "Content-Type: text/plain\r\n\r\njust a plain payload\n",
    ),
    [key.to_public()],
  )
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  // Both sides NotSigned -> status NotSigned (gopenpgp scenario_11 shape).
  assert_eq(cb.errors.length(), 2)
  assert_eq(cb.verified, [@api.NotSigned])
  assert_eq(cb.bodies, [("just a plain payload\n", "text/plain")])
}

///|
test "@mime.decrypt_mime: no verifiers skips on_verified entirely" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let inner = @mime.build_pgp_mime_signed("quiet body\n", key)
  let armored = @api.encrypt_to_recipients(@primitives.utf8_bytes(inner), [
    key.to_public(),
  ])
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[], callbacks=cb)
  assert_eq(cb.errors.length(), 0)
  assert_eq(cb.verified.length(), 0)
  assert_true(cb.bodies[0].0.contains("quiet body"))
}

///|
test "@mime.decrypt_mime: password path verifies inner signature" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let inner = @mime.build_pgp_mime_signed("password mime\n", key)
  let armored = @api.encrypt_with_password(@primitives.utf8_bytes(inner), "pp")
  let cb = new_callbacks()
  @mime.decrypt_mime(
    armored,
    [],
    verifiers=[key.to_public()],
    callbacks=cb,
    password="pp",
  )
  assert_eq(cb.errors.length(), 0)
  assert_eq(cb.verified, [@api.Ok])
  assert_true(cb.bodies[0].0.contains("password mime"))
}

///|
test "@mime.decrypt_mime: wrong key reports error, no delivery" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let other = @api.generate_key("Other <other@example.com>", bits=2048)
  let armored = @api.encrypt_to_recipients(@primitives.utf8_bytes("secret\n"), [
    key.to_public(),
  ])
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [other], verifiers=[], callbacks=cb)
  assert_eq(cb.errors.length(), 1)
  assert_eq(cb.bodies.length(), 0)
  assert_eq(cb.verified.length(), 0)
}

///|
test "@mime.decrypt_mime: non-mime plaintext payload with verifiers is NotSigned" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let armored = @api.encrypt_to_recipients(
    @primitives.utf8_bytes("Content-Type: text/plain\r\n\r\nplain payload\n"),
    [key.to_public()],
  )
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  assert_eq(cb.verified, [@api.NotSigned])
  assert_eq(cb.bodies, [("plain payload\n", "text/plain")])
}

///|
test "@mime.decrypt_mime: missing decryption material errors" {
  let cb = new_callbacks()
  @mime.decrypt_mime("not a pgp message", [], verifiers=[], callbacks=cb)
  assert_eq(cb.errors.length(), 1)
  assert_eq(cb.bodies.length(), 0)
}

///|
test "@mime.decrypt_mime: password path with verifiers and unsigned payload is NotSigned" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let armored = @api.encrypt_with_password(
    @primitives.utf8_bytes(
      "Content-Type: text/plain\r\n\r\nplain password payload\n",
    ),
    "pp",
  )
  let cb = new_callbacks()
  @mime.decrypt_mime(
    armored,
    [],
    verifiers=[key.to_public()],
    callbacks=cb,
    password="pp",
  )
  // gopenpgp scenario_11 shape: both sides unverified -> NOT_SIGNED with
  // two errors (the password path must not fake an Ok).
  assert_eq(cb.errors.length(), 2)
  assert_eq(cb.verified, [@api.NotSigned])
  assert_eq(cb.bodies, [("plain password payload\n", "text/plain")])
}

///|
test "@mime.decrypt_mime: proton shape (extra blank line) verifies ok" {
  let key = @api.generate_key("Proton <p@example.com>", bits=2048)
  // Signed data = part bytes including the trailing CRLF; the extra
  // blank line between part and boundary is the Proton builder shape.
  let part1 = "Content-Type: text/plain; charset=utf-8\r\n\r\nproton body\r\n"
  let sig = @api.sign_detached(@primitives.utf8_bytes(part1).exact_view(), key)
  let inner = "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"PB\"\r\n\r\n--PB\r\n" +
    part1 +
    "\r\n--PB\r\nContent-Type: application/pgp-signature\r\n\r\n" +
    sig +
    "\r\n--PB--\r\n"
  let armored = @api.encrypt_to_recipients(@primitives.utf8_bytes(inner), [
    key.to_public(),
  ])
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  assert_eq(cb.errors, [])
  assert_eq(cb.verified, [@api.Ok])
  assert_true(cb.bodies[0].0.contains("proton body"))
}

///|
test "@mime.decrypt_mime: embedded ok masks failed mime signature" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  // Inner multipart/signed whose body was tampered after signing; the
  // OPS signature over the tampered bytes itself verifies.
  let signed = @mime.build_pgp_mime_signed("authentic\n", key)
  let tampered = signed.replace(old="authentic", new="tampered")
  let armored = @api.sign_and_encrypt(
    @primitives.utf8_bytes(tampered).exact_view(),
    key,
    [key.to_public()],
  )
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  // gopenpgp scenario_03 shape: the Ok embedded side masks the failed
  // MIME side — no errors, final status Ok, body still delivered.
  assert_eq(cb.errors, [])
  assert_eq(cb.verified, [@api.Ok])
  assert_true(cb.bodies[0].0.contains("tampered"))
}

///|
test "@mime.decrypt_mime: unknown issuer embedded with unsigned mime" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let other = @api.generate_key("Other <o@example.com>", bits=2048)
  // Inline signature by `other`; the verifier list only contains `key`.
  let armored = @api.sign_and_encrypt(
    @primitives.utf8_bytes("Content-Type: text/plain\r\n\r\nunsigned mime\n").exact_view(),
    other,
    [key.to_public()],
  )
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  // gopenpgp scenario_21 shape: NoVerifier (embedded) + NotSigned (mime)
  // -> two errors, worst status NoVerifier.
  assert_eq(cb.errors.length(), 2)
  assert_eq(cb.verified, [@api.NoVerifier])
  assert_eq(cb.bodies, [("unsigned mime\n", "text/plain")])
}

///|
test "@mime.decrypt_mime: headerless payload delivers empty body" {
  let key = @api.generate_key("DecryptMime <dm@example.com>", bits=2048)
  let armored = @api.encrypt_to_recipients(
    @primitives.utf8_bytes("just text, no mime structure\n"),
    [key.to_public()],
  )
  let cb = new_callbacks()
  @mime.decrypt_mime(armored, [key], verifiers=[key.to_public()], callbacks=cb)
  // No blank line means everything is headers per RFC 5322 (net/mail
  // behaves the same inside gopenpgp): empty body, NotSigned + 2 errors.
  assert_eq(cb.verified, [@api.NotSigned])
  assert_eq(cb.bodies, [("", "text/plain")])
}
