// Hacker-round probes (2026-11-13), mailreader facet.

///|
/// The F23 StringBuilder rewrite turned the header loop from assignment
/// to append semantics: a malformed nameless header line (`:junk`) leaves
/// current_name empty, so the flush-before-new-header never fires and the
/// attacker's text is silently PREPENDED to the next real header's value.
test "a nameless header line cannot pollute the next header's value" {
  let headers = b"From: alice\r\n:junk\r\nSubject: real\r\n"
  assert_eq(header_value(headers, "subject"), Some("real"))
  assert_eq(header_value(headers, "from"), Some("alice"))
}

///|
/// Control (must stay green): normal parsing and folding still work.
test "ordinary header block still parses" {
  let headers = b"From: alice\r\nSubject: folded\r\n more\r\nX-Empty:\r\n"
  assert_eq(header_value(headers, "subject"), Some("folded more"))
  assert_eq(header_value(headers, "x-empty"), Some(""))
}
