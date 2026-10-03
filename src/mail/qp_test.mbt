///|
test "qp: printable text passes through" {
  let s = @primitives.utf8_bytes("Hello, world!")
  assert_eq(@mail.encode_quoted_printable(s.exact_view()), s)
}

///|
test "qp: equals and non-ascii encoded" {
  assert_eq(
    @mail.encode_quoted_printable(
      @primitives.utf8_bytes("foo=bar").exact_view(),
    ),
    @primitives.utf8_bytes("foo=3Dbar"),
  )
  // "café" UTF-8: 63 61 66 C3 A9
  assert_eq(
    @mail.encode_quoted_printable(@primitives.utf8_bytes("café").exact_view()),
    @primitives.utf8_bytes("caf=C3=A9"),
  )
}

///|
test "qp: trailing whitespace encoded, interior kept" {
  // interior WSP stays literal...
  assert_eq(
    @mail.encode_quoted_printable(
      @primitives.utf8_bytes("a \tb\r\nc").exact_view(),
    ),
    @primitives.utf8_bytes("a \tb\r\nc"),
  )
  // ...but the WSP directly before the break must be =09
  assert_eq(
    @mail.encode_quoted_printable(
      @primitives.utf8_bytes("a \t\r\nc").exact_view(),
    ),
    @primitives.utf8_bytes("a =09\r\nc"),
  )
  // same at end of data
  assert_eq(
    @mail.encode_quoted_printable(@primitives.utf8_bytes("x ").exact_view()),
    @primitives.utf8_bytes("x=20"),
  )
}

///|
test "qp: soft breaks keep lines under 76 and never split atoms" {
  let long = @primitives.utf8_bytes(
    "The quick brown fox jumps over the lazy dog and keeps running through the field",
  )
  let out = @mail.encode_quoted_printable(long.exact_view())
  // byte-level line-length check (QP output is pure ASCII)
  let mut maxline = 0
  let mut cur = 0
  for b in out {
    // line width counts chars before CRLF (the CR itself excluded)
    if b == b'\n' {
      if cur > maxline {
        maxline = cur
      }
      cur = 0
    } else if b != b'\r' {
      cur = cur + 1
    }
  }
  if cur > maxline {
    maxline = cur
  }
  assert_true(maxline <= 76)
  // roundtrip must restore the input
  assert_eq(@mime.decode_quoted_printable(out.exact_view()), long)
}

///|
test "qp: roundtrip over a mixed sample" {
  let sample = @primitives.utf8_bytes(
    "Mixed content: café, =sign, tab\there, and a very long sentence that will certainly need soft breaks somewhere in the middle of it.",
  )
  let out = @mail.encode_quoted_printable(sample.exact_view())
  assert_eq(@mime.decode_quoted_printable(out.exact_view()), sample)
}
