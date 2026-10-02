///|
test "single part defaults to text/plain" {
  let root = @mime.parse_mime_tree(
    @primitives.utf8_bytes("Subject: hi\r\n\r\nbody line"),
  )
  assert_eq(root.content_type.mimetype(), "text/plain")
  assert_eq(root.header("Subject"), Some("hi"))
  assert_eq(@utf8.decode_lossy(root.body.exact_view()), "body line")
  assert_true(root.parts.is_empty())
}

///|
test "multipart mixed: body and attachment" {
  let eml = "Content-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\nhello body\r\n--BB\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\n\r\nRAWDATA\r\n--BB--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  assert_true(root.is_multipart())
  assert_eq(root.parts.length(), 2)
  let (body, atts) = @mime.collect_body_and_attachments(root)
  match body {
    Some(b) => {
      assert_eq(b.mimetype, "text/plain")
      assert_eq(@utf8.decode_lossy(b.content.exact_view()), "hello body")
    }
    None => assert_true(false)
  }
  assert_eq(atts.length(), 1)
  assert_eq(atts[0].filename, Some("data.bin"))
  assert_eq(@utf8.decode_lossy(atts[0].data.exact_view()), "RAWDATA")
}

///|
test "alternative: html wins regardless of order" {
  let eml = "Content-Type: multipart/alternative; boundary=\"X\"\r\n\r\n--X\r\nContent-Type: text/plain\r\n\r\nplain version\r\n--X\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--X--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let (body, _atts) = @mime.collect_body_and_attachments(root)
  match body {
    Some(b) => {
      assert_eq(b.mimetype, "text/html")
      assert_eq(@utf8.decode_lossy(b.content.exact_view()), "<p>html</p>")
    }
    None => assert_true(false)
  }
}

///|
test "nested multipart/encrypted shape parses" {
  let eml = "Content-Type: multipart/encrypted; boundary=\"E\"\r\n\r\n--E\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--E\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP MESSAGE-----\r\npayload\r\n-----END PGP MESSAGE-----\r\n--E--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  assert_eq(root.parts.length(), 2)
  assert_eq(root.parts[0].content_type.mimetype(), "application/pgp-encrypted")
  assert_true(
    @utf8.decode_lossy(root.parts[1].body.exact_view()).contains(
      "BEGIN PGP MESSAGE",
    ),
  )
}

///|
test "binary leaf survives byte-exact" {
  // 8bit payload with non-UTF-8 bytes must not be corrupted by parsing.
  let head = @primitives.utf8_bytes(
    "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
  )
  let payload = Bytes::from_array([b'\x00', b'\xff', b'\xfe', b'\x0a', b'\x01'])
  let part_bytes = @primitives.concat2(head, payload)
  let eml = @primitives.concat3(
    @primitives.utf8_bytes(
      "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\n",
    ),
    part_bytes,
    @primitives.utf8_bytes("\r\n--B--\r\n"),
  )
  let root = @mime.parse_mime_tree(eml)
  assert_eq(root.parts.length(), 1)
  assert_eq(root.parts[0].body, payload)
  // The raw part span keeps the headers too (needed for signed parts).
  assert_eq(root.parts[0].raw, part_bytes)
}

///|
test "multipart without boundary raises" {
  let eml = @primitives.utf8_bytes(
    "Content-Type: multipart/mixed\r\n\r\nnothing",
  )
  assert_true(raises_bool(fn() raise { ignore(@mime.parse_mime_tree(eml)) }))
}

///|
test "multipart with no parts raises" {
  let eml = @primitives.utf8_bytes(
    "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\nno delimiters",
  )
  assert_true(raises_bool(fn() raise { ignore(@mime.parse_mime_tree(eml)) }))
}

///|
test "excessive nesting raises" {
  let mut eml = "leaf"
  for k in 0..<25 {
    let b = "B\{k}"
    eml = "Content-Type: multipart/mixed; boundary=\"\{b}\"\r\n\r\n--\{b}\r\n\{eml}\r\n--\{b}--\r\n"
  }
  assert_true(
    raises_bool(fn() raise {
      ignore(@mime.parse_mime_tree(@primitives.utf8_bytes(eml)))
    }),
  )
}

///|
test "no text leaves yields None body with attachments" {
  let eml = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: application/pdf\r\n\r\n%PDF\r\n--B--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let (body, atts) = @mime.collect_body_and_attachments(root)
  assert_true(body is None)
  assert_eq(atts.length(), 1)
}

///|
test "multiple plain leaves concatenate in tree order" {
  let eml = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\none\r\n--B\r\nContent-Type: text/plain\r\n\r\ntwo\r\n--B--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let (body, atts) = @mime.collect_body_and_attachments(root)
  assert_eq(atts.length(), 0)
  match body {
    Some(b) => assert_eq(@utf8.decode_lossy(b.content.exact_view()), "onetwo")
    None => assert_true(false)
  }
}

///|
test "text/csv is an attachment, not a body" {
  let eml = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/csv\r\n\r\na,b\r\n--B--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let (body, atts) = @mime.collect_body_and_attachments(root)
  assert_true(body is None)
  assert_eq(atts.length(), 1)
  assert_eq(atts[0].mimetype, "text/csv")
}

///|
test "attachment disposition on text part goes to attachments" {
  let eml = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\nContent-Disposition: attachment\r\n\r\nfile-ish\r\n--B--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let (body, atts) = @mime.collect_body_and_attachments(root)
  assert_true(body is None)
  assert_eq(atts.length(), 1)
  assert_true(atts[0].filename is None)
}

///|
test "filename falls back to content-type name" {
  let eml = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: application/octet-stream; name=\"x.bin\"\r\n\r\npayload\r\n--B--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let (_body, atts) = @mime.collect_body_and_attachments(root)
  assert_eq(atts[0].filename, Some("x.bin"))
}

///|
test "signed part raw span excludes boundary crlf" {
  // The CRLF before the closing boundary belongs to the boundary; the
  // raw span of part 1 must end without it (mime_canonicalize re-adds).
  let eml = "Content-Type: multipart/signed; boundary=\"S\"\r\n\r\n--S\r\nContent-Type: text/plain\r\n\r\nsigned body\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\nSIG\r\n--S--\r\n"
  let root = @mime.parse_mime_tree(@primitives.utf8_bytes(eml))
  let raw = @utf8.decode_lossy(root.parts[0].raw.exact_view())
  assert_true(raw.has_prefix("Content-Type: text/plain\r\n\r\nsigned body"))
  assert_false(raw.has_suffix("\r\n"))
}
