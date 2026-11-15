// Hacker-round probes (2026-11-13): F28 residual String/byte divergence.

///|
/// RFC 2046 §5.1.1 allows whitespace between the delimiter and CRLF, and
/// real MUAs emit it. The byte version (walk.mbt line_is_delim +
/// rest_is_padding) accepts; the String twin still demands an exact
/// match and throws the whole message away.
test "split_multipart tolerates transport whitespace on delimiter lines" {
  let parts = @mime.split_multipart(
    "--B \r\nA\r\n--B\t\r\nB\r\n--B--  \r\n", "B",
  )
  assert_eq(parts.length(), 2)
}

///|
/// A message missing its closing delimiter is tolerated by the byte
/// version (the trailing part is flushed at EOF); the String twin drops
/// the buffered part and raises "no multipart parts found".
test "split_multipart flushes an unclosed final part like the byte version" {
  let parts = @mime.split_multipart("--B\r\nA\r\n", "B")
  assert_eq(parts.length(), 1)
}

///|
/// Byte-version control: the same shapes parse fine through parse_mime_tree.
test "byte version accepts whitespace-padded and unclosed delimiters" {
  let tree = @mime.parse_mime_tree(
    @primitives.utf8_bytes(
      "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B \r\nA\r\n--B\t\r\nB\r\n--B--  \r\n",
    ),
  )
  assert_eq(tree.parts.length(), 2)
  let unclosed = @mime.parse_mime_tree(
    @primitives.utf8_bytes(
      "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nA\r\n",
    ),
  )
  assert_eq(unclosed.parts.length(), 1)
}

///|
/// Self-review F-R1: the byte version stops scanning at the close
/// delimiter — epilogue is ignored entirely. Without the stop flag the
/// String twin let an epilogue line shaped like the dash-boundary revive
/// a part (and turned close-only + epilogue from an error into a part).
test "split_multipart ignores the epilogue after the close delimiter" {
  let parts = @mime.split_multipart("--B\r\nA\r\n--B--\r\n--B\r\nZ\r\n", "B")
  assert_eq(parts.length(), 1)
  let raised = try {
    ignore(@mime.split_multipart("--B--\r\n--B\r\nx", "B"))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
