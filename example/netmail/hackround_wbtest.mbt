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

///|
/// Cleanup follow-up (agent report B#12): a mailbox name with a space
/// is one quoted-string argument — unquoted, `SELECT My Mail` splits
/// into two arguments and silently addresses the wrong mailbox.
test "imap_select quotes multi-word mailbox names (B#12)" {
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK completed\r\n",
    select_response(),
    b"a3 OK LOGOUT completed\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@example.com", "secret1")
  c.imap_select("My Mail")
  c.imap_logout()
  let mut saw_quoted = false
  for raw in f.sent {
    if bytes_lossy(raw).contains("SELECT \"My Mail\"") {
      saw_quoted = true
    }
  }
  assert_true(saw_quoted)
}

///|
/// Cleanup follow-up (agent report B#13): the 64 MiB byte budget bounds
/// the input, not the parse tree — a line of single-atom tokens costs a
/// node + String each (~20-30x the wire bytes). The node cap keeps the
/// tree bounded; 1M nodes is ~1000x any legitimate response.
test "parse_nodes refuses responses beyond the node cap (B#13)" {
  let raised = try {
    ignore(parse_nodes([Txt(@utf8.encode("1 ".repeat(1_200_000)))]))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Control: a modest response parses into its atoms.
  assert_eq(parse_nodes([Txt(@utf8.encode("1 2 3"))]).length(), 3)
}
