///|
/// Whitebox tests for the IMAP response syntax scanner (audit F24): the
/// paren scanner used to recurse without a depth cap, so one line of
/// `(` from a hostile server overflowed the native stack and aborted
/// the process — pre-authentication, on the greeting line.

///|
test "imap syntax: nesting beyond the cap raises instead of aborting (F24)" {
  let segs = [Seg::Txt(Bytes::from_array(Array::makei(200, _ => b'(')))]
  let raised = try {
    ignore(parse_nodes(segs))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "imap syntax: nesting under the cap still parses (F24)" {
  // 40 nested lists close cleanly, one level under MAX_PARENS_DEPTH.
  let bytes : Array[Byte] = Array::makei(80, i => {
    if i < 40 {
      b'('
    } else {
      b')'
    }
  })
  let nodes = parse_nodes([Seg::Txt(Bytes::from_array(bytes))])
  guard nodes.length() == 1 else { fail("expected one node") }
  guard nodes[0] is Parens(_) else { fail("expected a parens node") }
}

///|
test "a literal beyond the 4 MiB cap is refused (F27)" {
  let raw = Bytes::make(20, b'a')
  // Craft a raw line ending in {5000000}: above max_literal, below the
  // old 100 MB one. read_raw_line semantics: the terminator is already
  // stripped, so the marker's `}` is the last octet.
  let line = raw.add(@utf8.encode(" {5000000}"))
  let budget = LineBudget::new(536_870_912L)
  let fake = FakeLiteralSock::{ lines: [line], pos: 0, }
  let raised = try {
    ignore(read_logical_line(fake, budget))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "the session byte budget is charged and enforced (F27)" {
  let line = Bytes::make(64, b'x')
  // A tiny budget: the second line must trip it.
  let budget = LineBudget::new(100L)
  let fake = FakeLiteralSock::{ lines: [line, line], pos: 0, }
  ignore(read_logical_line(fake, budget))
  let raised = try {
    ignore(read_logical_line(fake, budget))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
priv struct FakeLiteralSock {
  lines : Array[Bytes]
  mut pos : Int32
}

///|
impl Socket for FakeLiteralSock with fn read_raw_line(self) -> Bytes raise {
  guard self.pos < self.lines.length() else { @error.fail("fake: exhausted") }
  let l = self.lines[self.pos]
  self.pos = self.pos + 1
  l
}

///|
impl Socket for FakeLiteralSock with fn read_exact(_self, n : Int32) -> Bytes raise {
  Bytes::make(n, b'L')
}

///|
impl Socket for FakeLiteralSock with fn read_line(_self) -> String raise {
  @error.fail("unused")
}

///|
impl Socket for FakeLiteralSock with fn write_all(_self, data : Bytes) -> Unit raise {
  ignore(data)
}

///|
impl Socket for FakeLiteralSock with fn close(_self) -> Unit {

}
