// Hacker-round probes (2026-11-13), netmail facet.

///|
/// F31 gated the envelope addresses but left ehlo_domain unvalidated —
/// the same pub-API caller bypassing @mail can inject commands through
/// the EHLO line instead.
async test "smtp: EHLO domain rejects CRLF command injection (F31 residual)" {
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  let raised = try {
    smtp_send(
      f,
      "body\r\n",
      "a@b.example",
      ["c@d.example"],
      "relay.example\r\nRCPT TO:<evil@x.example>",
      None,
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
