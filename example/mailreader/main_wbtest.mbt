///|
/// CLI-level tests for example/mailreader's own helpers (arg parsing,
/// header unfolding, attachment-name sanitization). Protocol-level
/// tests live with the library in src/netmail/imap_wbtest.mbt.

///|
test "cli: sanitize_filename blocks traversal and weird names" {
  assert_eq(sanitize_filename("report.txt"), "report.txt")
  assert_eq(sanitize_filename("../../.ssh/authorized_keys"), "authorized_keys")
  assert_eq(sanitize_filename("..\\..\\evil"), "evil")
  assert_eq(sanitize_filename(".."), "")
  assert_eq(sanitize_filename("."), "")
  assert_eq(sanitize_filename(""), "")
  assert_eq(sanitize_filename("a\nb"), "")
  assert_eq(sanitize_filename("with space.pdf"), "with space.pdf")
}

///|
test "cli: header_value unfolds folded headers keeping one space" {
  let headers : Bytes = b"From: John\r\n Smith <a@b.example>\r\nSubject: hi\r\n\r\n"
  assert_eq(header_value(headers, "from").unwrap(), "John Smith <a@b.example>")
  assert_eq(header_value(headers, "subject").unwrap(), "hi")
  assert_eq(header_value(headers, "date"), None)
}

///|
test "cli: CLI --fetch with a non-numeric UID fails loudly" {
  let raised = try {
    ignore(
      parse_args(["--user", "u@163.com", "--pass-env", "P", "--fetch", "abc"]),
    )
    false
  } catch {
    e => e.to_string().contains("numeric UID")
  }
  assert_true(raised)
  let raised2 = try {
    ignore(parse_args(["--fetch", "-5", "--user", "u", "--pass-env", "P"]))
    false
  } catch {
    e => e.to_string().contains("--fetch expects a")
  }
  assert_true(raised2)
}
