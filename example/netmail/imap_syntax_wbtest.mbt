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
