///|
test "rfc5322_date golden vectors" {
  // epoch
  assert_eq(@mail.rfc5322_date(0L, 0), "Thu, 01 Jan 1970 00:00:00 +0000")
  // positive half/full hour zones
  assert_eq(@mail.rfc5322_date(0L, 480), "Thu, 01 Jan 1970 08:00:00 +0800")
  assert_eq(@mail.rfc5322_date(0L, 345), "Thu, 01 Jan 1970 05:45:00 +0545")
  // negative zone crosses the epoch backwards
  assert_eq(@mail.rfc5322_date(0L, -450), "Wed, 31 Dec 1969 16:30:00 -0730")
  // 2026-10-02 10:00 +0800 == 02:00 UTC (python datetime verified)
  assert_eq(
    @mail.rfc5322_date(1790906400L, 480),
    "Fri, 02 Oct 2026 10:00:00 +0800",
  )
  // 2024-03-01 (leap year, right after Feb 29)
  assert_eq(
    @mail.rfc5322_date(1709251200L, 0),
    "Fri, 01 Mar 2024 00:00:00 +0000",
  )
  // negative epoch exercises the floor-division and weekday paths
  assert_eq(@mail.rfc5322_date(-1L, 0), "Wed, 31 Dec 1969 23:59:59 +0000")
}

///|
test "format_address quoting rules" {
  let plain : @mail.MailAddress = { display_name: "", addr: "a@b.example", }
  assert_eq(@mail.format_address(plain), "a@b.example")
  let atext_name : @mail.MailAddress = {
    display_name: "Alice-Simple_1",
    addr: "a@b.example",
  }
  assert_eq(@mail.format_address(atext_name), "Alice-Simple_1 <a@b.example>")
  // space and dot are NOT atext -> quoted
  let spaced : @mail.MailAddress = {
    display_name: "John Q. Public",
    addr: "john@example.com",
  }
  assert_eq(
    @mail.format_address(spaced),
    "\"John Q. Public\" <john@example.com>",
  )
  // quotes inside the name are escaped
  let evil : @mail.MailAddress = {
    display_name: "The \"Boss\"",
    addr: "boss@example.com",
  }
  assert_eq(
    @mail.format_address(evil),
    "\"The \\\"Boss\\\"\" <boss@example.com>",
  )
  // CRLF injection and non-ASCII fail fast
  let inj : @mail.MailAddress = { display_name: "x", addr: "a@b\r\nBCC: x", }
  assert_true(raises_bool(fn() raise { ignore(@mail.format_address(inj)) }))
}

///|
test "message_id shape and domain validation" {
  let r : Bytes = Bytes::from_array([
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\x09',
    b'\x0a', b'\x0b', b'\x0c', b'\x0d', b'\x0e', b'\x0f', b'\x10',
  ])
  assert_eq(
    @mail.message_id(r, "mailpgp.example"),
    "<0102030405060708090a0b0c0d0e0f10@mailpgp.example>",
  )
  assert_true(raises_bool(fn() raise { ignore(@mail.message_id(r, "")) }))
  assert_true(
    raises_bool(fn() raise { ignore(@mail.message_id(r, "bad domain")) }),
  )
  assert_true(raises_bool(fn() raise { ignore(@mail.message_id(r, "a@b")) }))
}

///|
fn raises_bool(f : () -> Unit raise) -> Bool {
  try {
    f()
    false
  } catch {
    _ => true
  }
}
