///|
test "qp hex sequences decode" {
  let data = @primitives.utf8_bytes("=48=65=6C=6C=6F")
  assert_eq(
    @mime.decode_quoted_printable(data.exact_view()),
    @primitives.utf8_bytes("Hello"),
  )
}

///|
test "qp soft breaks drop the equals" {
  let crlf = @primitives.utf8_bytes("foo=\r\nbar")
  assert_eq(
    @mime.decode_quoted_printable(crlf.exact_view()),
    @primitives.utf8_bytes("foobar"),
  )
  let lf = @primitives.utf8_bytes("foo=\nbar")
  assert_eq(
    @mime.decode_quoted_printable(lf.exact_view()),
    @primitives.utf8_bytes("foobar"),
  )
}

///|
test "qp decodes multi-byte utf8" {
  let data = @primitives.utf8_bytes("caf=C3=A9")
  assert_eq(
    @mime.decode_quoted_printable(data.exact_view()),
    @primitives.utf8_bytes("café"),
  )
}

///|
test "qp equals literal via =3D" {
  let data = @primitives.utf8_bytes("a=3Db")
  assert_eq(
    @mime.decode_quoted_printable(data.exact_view()),
    @primitives.utf8_bytes("a=b"),
  )
}

///|
test "qp invalid sequences kept literally" {
  let bad = @primitives.utf8_bytes("a=zb")
  assert_eq(
    @mime.decode_quoted_printable(bad.exact_view()),
    @primitives.utf8_bytes("a=zb"),
  )
  let short = @primitives.utf8_bytes("x=A")
  assert_eq(
    @mime.decode_quoted_printable(short.exact_view()),
    @primitives.utf8_bytes("x=A"),
  )
}

///|
test "qp trailing equals treated as padding" {
  let data = @primitives.utf8_bytes("abc=")
  assert_eq(
    @mime.decode_quoted_printable(data.exact_view()),
    @primitives.utf8_bytes("abc"),
  )
}

///|
test "identity transfer encodings pass through" {
  let data = @primitives.utf8_bytes("plain\r\ntext")
  assert_eq(@mime.decode_transfer_encoding(data.exact_view(), None), data)
  assert_eq(
    @mime.decode_transfer_encoding(data.exact_view(), Some("7bit")),
    data,
  )
  assert_eq(
    @mime.decode_transfer_encoding(data.exact_view(), Some("8Bit")),
    data,
  )
  assert_eq(
    @mime.decode_transfer_encoding(data.exact_view(), Some("binary")),
    data,
  )
  // Unknown encodings pass through instead of failing the message
  // (gomime behavior).
  assert_eq(
    @mime.decode_transfer_encoding(data.exact_view(), Some("uuencode")),
    data,
  )
}

///|
test "base64 with newlines decodes" {
  let encoded = @primitives.utf8_bytes("SGVsbG8s\r\nIE1JTUU=")
  let decoded = @mime.decode_transfer_encoding(
    encoded.exact_view(),
    Some("base64"),
  )
  assert_eq(@utf8.decode_lossy(decoded.exact_view()), "Hello, MIME")
}

///|
test "base64 failure raises for per-part degradation" {
  let encoded = @primitives.utf8_bytes("not!!!valid")
  let raised = try {
    ignore(@mime.decode_transfer_encoding(encoded.exact_view(), Some("base64")))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "quoted-printable dispatch" {
  let data = @primitives.utf8_bytes("=41=42\r\nnext")
  assert_eq(
    @mime.decode_transfer_encoding(data.exact_view(), Some("quoted-printable")),
    @primitives.utf8_bytes("AB\r\nnext"),
  )
}
