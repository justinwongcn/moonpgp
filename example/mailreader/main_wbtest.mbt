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
test "cli: boolean flag --resync must not swallow the next argument (M1)" {
  // Documented shape: --resync combines with --fetch. The parse loop
  // treated the boolean flag as value-taking, so --resync consumed the
  // next token as its value and skipped it — this raised
  // "unknown flag '42'" on the documented combination, and
  // "--resync --out DIR" silently dropped --out.
  let cfg = parse_args([
    "--resync", "--fetch", "42", "--user", "u", "--pass-env", "P",
  ])
  assert_true(cfg.resync)
  assert_eq(cfg.fetch_uid, Some(42))
  let cfg2 = parse_args([
    "--resync", "--out", "/tmp/x", "--user", "u", "--pass-env", "P",
  ])
  assert_eq(cfg2.out_dir, "/tmp/x")
  assert_true(cfg2.resync)
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

///|
test "sanitize_filename keeps the separator out of the base (F22)" {
  // Supplementary-plane char before the separator: the old char-count
  // scan vs UTF-16 slice drift let a leading '/' survive into the base.
  assert_eq(sanitize_filename("😀/x"), "x")
  // The drifted base used to be "/..", passing the dotdot whitelist.
  assert_eq(sanitize_filename("😀x/../.."), "")
  // Ordinary names behave as before.
  assert_eq(sanitize_filename("report.pdf"), "report.pdf")
  assert_eq(sanitize_filename("a/b/c.txt"), "c.txt")
  assert_eq(sanitize_filename(".."), "")
  assert_eq(sanitize_filename(""), "")
}

///|
test "uidvalidity persistence accepts the recorded generation (F26)" {
  let cfg = Config::new()
  cfg.host = "imap.test"
  cfg.out_dir = "/tmp"
  let user = "alice@test"
  record_uidvalidity(cfg, user, "INBOX", 42)
  // Same generation: fine.
  check_uidvalidity(cfg, user, "INBOX", 42)
  // A different folder is independent.
  check_uidvalidity(cfg, user, "Archive", 7)
}

///|
test "uidvalidity mismatch refuses the fetch (F26)" {
  let cfg = Config::new()
  cfg.host = "imap.test2"
  cfg.out_dir = "/tmp"
  let user = "bob@test"
  record_uidvalidity(cfg, user, "INBOX", 100)
  let raised = try {
    check_uidvalidity(cfg, user, "INBOX", 200)
    false
  } catch {
    e =>
      // The refusal names the changed generation.
      e.to_string().contains("UIDVALIDITY")
  }
  assert_true(raised)
}
