///|
/// LineBuffer discipline tests: the fill callback delivers scripted
/// chunks, so chunk boundaries can cut a line, a CRLF pair, a literal
/// length, or the literal body itself. These tests encode the
/// byte-safety invariant (mail-fetch plan §4.1): bytes are never
/// dropped when the three read disciplines interleave on one buffer.
/// Native-only because only the native backend constructs LineBuffer.

///|
#cfg(target="native")
fn script_buffer(chunks : Array[Bytes]) -> LineBuffer {
  let mut pos = 0
  let fill = fn(buf : FixedArray[Byte]) -> Int32 {
    guard pos < chunks.length() else { return 0 }
    let c = chunks[pos]
    pos = pos + 1
    for i in 0..<c.length() {
      buf[i] = c[i]
    }
    c.length()
  }
  LineBuffer::{ buf: FixedArray::make(16, b'\x00'), rstart: 0, rend: 0, fill, }
}

///|
#cfg(target="native")
test "line_buffer: read_line reassembles a line cut across chunks" {
  let lb = script_buffer([b"Hel", b"lo\r\nwor", b"ld\r\n"])
  assert_eq(lb.read_line(), "Hello")
  assert_eq(lb.read_line(), "world")
}

///|
#cfg(target="native")
test "line_buffer: CRLF pair cut across chunks is one terminator" {
  let lb = script_buffer([b"abc\r", b"\ndef\r\n"])
  assert_eq(lb.read_line(), "abc")
  assert_eq(lb.read_line(), "def")
}

///|
#cfg(target="native")
test "line_buffer: read_exact keeps remainder for later reads" {
  // 8-byte literal cut mid-chunk; the trailing 'Z' must survive
  let lb = script_buffer([b"XXXXYYYYZ", b"REST\r\n"])
  assert_eq(bytes_to_str(lb.read_exact(8)), "XXXXYYYY")
  assert_eq(bytes_to_str(lb.read_raw_line()), "ZREST")
}

///|
#cfg(target="native")
test "line_buffer: read_exact spans many refills on a tiny buffer" {
  // buffer capacity 16; demand 40 bytes from 5-byte chunks
  let lb = script_buffer([
    b"01234", b"56789", b"abcde", b"fghij", b"klmno", b"pqrst", b"uvwxy", b"z0123",
    b"45678", b"END\r\n",
  ])
  assert_eq(
    bytes_to_str(lb.read_exact(40)),
    "0123456789abcdefghijklmnopqrstuvwxyz0123",
  )
  assert_eq(bytes_to_str(lb.read_raw_line()), "45678END")
}

///|
#cfg(target="native")
test "line_buffer: read_raw_line holds CR across chunks, keeps bare CR" {
  // "ab\r| \n": CR held over the chunk edge, CRLF stripped.
  // "cd\r\r\n": first CR is data, second CR + LF is the terminator.
  let lb = script_buffer([b"ab\r", b"\ncd\r\r\ne"])
  assert_eq(bytes_to_str(lb.read_raw_line()), "ab")
  assert_eq(bytes_to_str(lb.read_raw_line()), "cd\r")
  let raised = try {
    ignore(lb.read_raw_line())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
#cfg(target="native")
test "line_buffer: read_exact of zero consumes nothing" {
  let lb = script_buffer([b"DATA\r\n"])
  assert_eq(lb.read_exact(0).length(), 0)
  assert_eq(lb.read_line(), "DATA")
}

///|
#cfg(target="native")
test "line_buffer: the three disciplines interleave without byte loss" {
  // reviewer-validated sequence: line, raw line, exact, line
  let lb = script_buffer([
    b"* 4 FET", b"CH (UID 4 BO", b"DY[] {5}\r\n", b"abc\r\n", b"de) FLAGS (\\S",
    b"een)\r\n", b"* 4 EXISTS\r\n",
  ])
  assert_eq(lb.read_line(), "* 4 FETCH (UID 4 BODY[] {5}")
  assert_eq(bytes_to_str(lb.read_exact(5)), "abc\r\n")
  assert_eq(bytes_to_str(lb.read_raw_line()), "de) FLAGS (\\Seen)")
  assert_eq(lb.read_line(), "* 4 EXISTS")
}

///|
#cfg(target="native")
test "line_buffer: EOF mid-read raises" {
  let lb = script_buffer([b"partial line"])
  let raised = try {
    ignore(lb.read_line())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
