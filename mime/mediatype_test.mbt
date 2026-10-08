///|
/// Assert helper: does `f` raise?
fn raises_bool(f : () -> Unit raise) -> Bool {
  try {
    f()
    false
  } catch {
    _ => true
  }
}

///|
test "parse content type basic" {
  let mt = @mime.parse_content_type("text/plain; charset=utf-8")
  assert_eq(mt.mimetype(), "text/plain")
  assert_eq(mt.param("charset"), Some("utf-8"))
  assert_eq(mt.param("missing"), None)
}

///|
test "quoted boundary containing semicolon" {
  let mt = @mime.parse_content_type("multipart/mixed; boundary=\"xyz;123\"")
  assert_eq(mt.param("boundary"), Some("xyz;123"))
}

///|
test "types lowered, parameter values keep case" {
  let mt = @mime.parse_content_type(
    "MULTIPART/AlTeRnAtIvE; BOUNDARY=abc; CHARSET=UTF-8",
  )
  assert_eq(mt.mimetype(), "multipart/alternative")
  assert_eq(mt.param("boundary"), Some("abc"))
  assert_eq(mt.param("charset"), Some("UTF-8"))
}

///|
test "quoted pair escapes resolved" {
  let mt = @mime.parse_content_type("multipart/mixed; boundary=\"a\\\"b\\\\c\"")
  assert_eq(mt.param("boundary"), Some("a\"b\\c"))
}

///|
test "duplicate parameter: last wins" {
  let mt = @mime.parse_content_type("text/plain; a=1; a=2")
  assert_eq(mt.param("a"), Some("2"))
}

///|
test "empty segments and trailing semicolon tolerated" {
  let mt = @mime.parse_content_type("text/plain;;charset=us-ascii;")
  assert_eq(mt.mimetype(), "text/plain")
  assert_eq(mt.param("charset"), Some("us-ascii"))
}

///|
test "unquoted value with surrounding space" {
  let mt = @mime.parse_content_type("multipart/mixed;  boundary = plain value ")
  assert_eq(mt.param("boundary"), Some("plain value"))
}

///|
test "invalid content types raise" {
  assert_true(
    raises_bool(fn() raise { ignore(@mime.parse_content_type("text")) }),
  )
  assert_true(
    raises_bool(fn() raise { ignore(@mime.parse_content_type("text/")) }),
  )
  assert_true(
    raises_bool(fn() raise { ignore(@mime.parse_content_type("/plain")) }),
  )
  assert_true(
    raises_bool(fn() raise {
      ignore(@mime.parse_content_type("text/plain; novalue"))
    }),
  )
  assert_true(
    raises_bool(fn() raise {
      ignore(@mime.parse_content_type("text/plain; =x"))
    }),
  )
  assert_true(
    raises_bool(fn() raise {
      ignore(@mime.parse_content_type("text/plain; b=\"open"))
    }),
  )
}

///|
test "disposition-shaped values parse via parse_header_params" {
  let (token, params) = @mime.parse_header_params(
    "attachment; filename=\"report.pdf\"; size=12",
  )
  assert_eq(token, "attachment")
  assert_eq(params, [("filename", "report.pdf"), ("size", "12")])
}
