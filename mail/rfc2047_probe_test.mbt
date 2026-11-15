// Hacker-round probes (2026-11-13): F21 residual control-character paths.
// Each test asserts the DESIRED behavior; a red run confirms the defect.

///|
/// Bare C0 controls in raw (non-encoded-word) header text must not reach
/// the terminal: strip_ctl only covers encoded-word payloads today, so a
/// plain `Subject: \x1B[2J` forges terminal escapes for free.
test "bare C0 in raw header text is stripped from decode_rfc2047 output" {
  let out = @mail.decode_rfc2047("a\u{1B}[2Jb\u{7}c")
  assert_false(out.contains("\u{1B}"))
  assert_false(out.contains("\u{7}"))
  assert_eq(out, "a[2Jbc")
}

///|
/// C1 controls (U+0080–U+009F) ride through both the byte-level strip_ctl
/// (0xC2 0x9B both >= 0x20) and the encode-side require_no_ctl — UTF-8 CSI
/// (U+009B) executes as an escape on xterm-family terminals, U+0085 NEL
/// forges list rows without touching the stripped CR/LF.
test "C1 controls are stripped from encoded-word decode output" {
  // B64 "wps=" = C2 9B (U+009B CSI); "woU=" = C2 85 (U+0085 NEL).
  let csi = @mail.decode_rfc2047("=?utf-8?B?wps=?=")
  assert_false(csi.contains("\u{9B}"))
  let nel = @mail.decode_rfc2047("=?utf-8?B?woU=?=")
  assert_false(nel.contains("\u{85}"))
}

///|
/// DEL (U+007F) survives byte-level strip_ctl (v >= 0x20 passes it) and
/// the encode-side gate alike; it belongs to the same stripped class.
test "DEL is stripped from decode_rfc2047 output" {
  assert_false(@mail.decode_rfc2047("a\u{7F}b").contains("\u{7F}"))
}

///|
/// Control test (must stay green): legitimate non-ASCII survives the
/// filter — é is U+00E9, above the C1 band, and tab stays legal folding
/// whitespace.
test "non-ASCII text and tab survive the control filter" {
  assert_eq(@mail.decode_rfc2047("café"), "café")
  assert_eq(@mail.decode_rfc2047("=?utf-8?B?Y2Fmw6k=?="), "café")
  assert_eq(@mail.decode_rfc2047("a\tb"), "a\tb")
}

///|
/// The F21 regression suite's CR/LF case was vacuous: its B64 payload had
/// a leading space, strict base64 rejected the whole word, and the raw
/// fallback (which never contained CR/LF) made the assertion pass with
/// strip_ctl deleted. This is the real vector, no padding.
test "CR/LF inside an encoded word is stripped (non-vacuous regression)" {
  let out = @mail.decode_rfc2047("=?utf-8?B?YQ0KYg==?=")
  assert_false(out.contains("\r"))
  assert_false(out.contains("\n"))
  assert_eq(out, "ab")
}
