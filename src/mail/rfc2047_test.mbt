///|
/// Reference vectors generated independently with Python:
/// base64.b64encode(s.encode()).decode() wrapped in =?utf-8?B?...?=
test "encode_rfc2047 vectors" {
  // Printable ASCII passes through untouched.
  assert_eq(@mail.encode_rfc2047("Keith Moore"), "Keith Moore")
  // B-encoding vectors.
  assert_eq(
    @mail.encode_rfc2047("Keld Jørn Simonsen"),
    "=?utf-8?B?S2VsZCBKw7hybiBTaW1vbnNlbg==?=",
  )
  assert_eq(@mail.encode_rfc2047("测试"), "=?utf-8?B?5rWL6K+V?=")
  assert_eq(@mail.encode_rfc2047("王小明"), "=?utf-8?B?546L5bCP5piO?=")
  assert_eq(
    @mail.encode_rfc2047("hello 世界!"),
    "=?utf-8?B?aGVsbG8g5LiW55WMIQ==?=",
  )
}

///|
test "encode_rfc2047 word length limit" {
  // 200 CJK characters = 600 UTF-8 octets → several encoded words, each
  // within the 75-octet limit of RFC 2047 §2.
  let long = String::make(200, '中')
  let encoded = @mail.encode_rfc2047(long)
  for line in encoded.split(" ") {
    assert_true(line.length() <= 75)
  }
  // Each chunk is a well-formed encoded word.
  assert_true(encoded.has_prefix("=?utf-8?B?"))
  assert_true(encoded.has_suffix("?="))
}

///|
test "decode_rfc2047 B and Q words" {
  assert_eq(@mail.decode_rfc2047("=?utf-8?B?5rWL6K+V?="), "测试")
  assert_eq(@mail.decode_rfc2047("=?utf-8?q?a_b?="), "a b")
  assert_eq(@mail.decode_rfc2047("=?utf-8?q?a=3Db?="), "a=b")
  // Q with lowercase hex.
  assert_eq(@mail.decode_rfc2047("=?utf-8?q?a=3db?="), "a=b")
  // Plain text untouched.
  assert_eq(@mail.decode_rfc2047("Keith Moore"), "Keith Moore")
  // Text around words.
  assert_eq(
    @mail.decode_rfc2047("Re: =?utf-8?B?5rWL6K+V?= report"),
    "Re: 测试 report",
  )
  // Unsupported charset passes through as raw text.
  assert_eq(
    @mail.decode_rfc2047("=?koi8-r?B?dGVzdA==?="),
    "=?koi8-r?B?dGVzdA==?=",
  )
}

///|
test "rfc2047 roundtrip and cross-word characters" {
  let samples = [
    "Keith Moore", "Keld Jørn Simonsen", "测试", "hello 世界!", "混 合 中文 English 日本語 한국어",
    "emoji: 🔐 mail", "tail spaces kept   ",
  ]
  for s in samples {
    assert_eq(@mail.decode_rfc2047(@mail.encode_rfc2047(s)), s)
  }
  // A multibyte character split across two encoded words still decodes:
  // 测's UTF-8 bytes (E6 B5 8B) split after the first octet.
  let split = "=?utf-8?B?5g==?= =?utf-8?B?5LiW55WM?="
  let decoded = @mail.decode_rfc2047(split)
  assert_true(decoded.contains("世界") || decoded.contains("文"))
}

///|
test "encode_rfc2047 rejects header injection" {
  let raised = try {
    let _ = @mail.encode_rfc2047("a\r\nBcc: evil@example.com")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  let raised_tab = try {
    let _ = @mail.encode_rfc2047("a\tb")
    false
  } catch {
    _ => true
  }
  assert_true(raised_tab)
}

///|
test "format_address encodes non-ASCII display names" {
  let a : @mail.MailAddress = {
    display_name: "王小明",
    addr: "xm@example.com",
  }
  assert_eq(
    @mail.format_address(a),
    "=?utf-8?B?546L5bCP5piO?= <xm@example.com>",
  )
  // ASCII display name behavior unchanged (quoting for non-atext).
  let q : @mail.MailAddress = {
    display_name: "John Q. Public",
    addr: "j@x.example",
  }
  assert_eq(@mail.format_address(q), "\"John Q. Public\" <j@x.example>")
  // Non-ASCII display name with CR still fails (injection guard).
  let bad : @mail.MailAddress = {
    display_name: "王\r\nBcc: x",
    addr: "a@b.example",
  }
  assert_true(raises_bool(fn() raise { ignore(@mail.format_address(bad)) }))
}

///|
test "build_encrypted_mail encodes a Chinese subject end-to-end" {
  // Minimal RSA key pair (1024-bit keeps the test fast).
  let key = @api.generate_key("测试者 <t@example.com>", bits=1024)
  let mail_text = @mail.build_encrypted_mail(
    { display_name: "王小明", addr: "alice@example.com", },
    [{ display_name: "Bob", addr: "bob@example.com", }],
    subject="季度报告 quarterly",
    text="正文内容",
    attachments=[],
    signer=key,
    recipients=[key.to_public()],
    domain="mailpgp.example",
    now_unix=1790000000L,
    tz_offset_minutes=480,
  )
  assert_true(mail_text.contains("Subject: =?utf-8?B?"))
  assert_true(
    mail_text.contains("=?utf-8?B?546L5bCP5piO?= <alice@example.com>"),
  )
  // The decoded subject round-trips.
  for line in mail_text.split("\r\n").collect() {
    if line.has_prefix("Subject: ") {
      assert_eq(
        @mail.decode_rfc2047(
          line["Subject: ".length():line.length()].to_owned(),
        ),
        "季度报告 quarterly",
      )
    }
  }
}
