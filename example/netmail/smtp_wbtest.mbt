///|
/// Offline SMTP state-machine tests: a scripted fake Sock drives
/// read_reply/smtp_send and records every client write, so the full
/// wire conversation is asserted without any network. White-box file:
/// the state machine's helpers are package-private. Async migration
/// (plan tls-transport M1): same scripts, same assertions — only the
/// seam changed from sync Socket to async Sock.

///|
priv struct FakeSock {
  script : Array[String]
  mut script_pos : Int
  sent_raw : Array[Bytes]
  mut closes : Int
}

///|
fn fake_sock(script : Array[String]) -> FakeSock {
  FakeSock::{ script, script_pos: 0, sent_raw: [], closes: 0, }
}

///|
impl Sock for FakeSock with fn read_line(self) -> String raise {
  guard self.script_pos < self.script.length() else {
    @error.fail("fake: script exhausted (server closed)")
  }
  let line = self.script[self.script_pos]
  self.script_pos = self.script_pos + 1
  line
}

///|
impl Sock for FakeSock with fn write_all(self, data : Bytes) -> Unit raise {
  self.sent_raw.push(data)
}

///|
impl Sock for FakeSock with fn close(self) -> Unit {
  self.closes = self.closes + 1
}

///|
fn bytes_to_str(data : Bytes) -> String {
  let sb = StringBuilder()
  for b in data {
    match b.to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
  }
  sb.to_string()
}

///|
fn sent_lines(f : FakeSock) -> Array[String] {
  let out : Array[String] = []
  for raw in f.sent_raw {
    out.push(bytes_to_str(raw))
  }
  out
}

///|
fn new_fake() -> FakeSock {
  let script = [
    "220 mini-sink ESMTP", "250-mini-sink hello", "250 AUTH PLAIN", "235 ok", "250 ok",
    "250 ok", "354 go", "250 stored", "221 bye",
  ]
  fake_sock(script)
}

///|
async test "smtp: full successful conversation" {
  let f = new_fake()
  smtp_send(
    f,
    "body line\r\n.subject line\r\n",
    "alice@example.com",
    ["bob@example.com"],
    "mailpgp.example",
    Some(("user", "pass")),
  )
  let cmds = sent_lines(f)
  assert_eq(cmds[0], "EHLO mailpgp.example\r\n")
  assert_true(cmds[1].has_prefix("AUTH PLAIN "))
  // base64("\0user\0pass") = AHVzZXIAcGFzcw==
  assert_eq(cmds[1], "AUTH PLAIN AHVzZXIAcGFzcw==\r\n")
  assert_eq(cmds[2], "MAIL FROM:<alice@example.com>\r\n")
  assert_eq(cmds[3], "RCPT TO:<bob@example.com>\r\n")
  assert_eq(cmds[4], "DATA\r\n")
  // dot-stuffing: the line starting with '.' gains one dot; CRLF kept
  assert_eq(cmds[5], "body line\r\n..subject line\r\n")
  assert_eq(cmds[6], ".\r\n")
  assert_eq(cmds[7], "QUIT\r\n")
}

///|
async test "smtp: no-auth conversation skips AUTH" {
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  smtp_send(f, "plain\r\n", "a@b.example", ["c@d.example"], "x.example", None)
  let cmds = sent_lines(f)
  assert_eq(cmds[0], "EHLO x.example\r\n")
  assert_eq(cmds[1], "MAIL FROM:<a@b.example>\r\n")
}

///|
async test "smtp: multiple envelope recipients in order" {
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "250 ok", "354 go", "250 stored",
    "221 bye",
  ])
  smtp_send(
    f,
    "hi\r\n",
    "a@b.example",
    ["c@d.example", "e@f.example"],
    "x.example",
    None,
  )
  let cmds = sent_lines(f)
  assert_eq(cmds[2], "RCPT TO:<c@d.example>\r\n")
  assert_eq(cmds[3], "RCPT TO:<e@f.example>\r\n")
}

///|
async test "smtp: dot-stuffing table (RFC 5321 §4.5.2)" {
  // first character of the message included; lone dot doubles
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  smtp_send(f, "..x\r\n.\r\na.b\r\n", "a@b.example", ["c@d.example"], "x", None)
  let cmds = sent_lines(f)
  assert_eq(cmds[4], "...x\r\n..\r\na.b\r\n")
}

///|
async test "smtp: message without trailing CRLF gets one before the dot" {
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  smtp_send(f, "no trailing newline", "a@b.example", ["c@d.example"], "x", None)
  let cmds = sent_lines(f)
  assert_eq(cmds[4], "no trailing newline\r\n")
}

///|
async test "smtp: bare LF in the message is normalized to CRLF" {
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  smtp_send(f, "lf line\nsecond\n", "a@b.example", ["c@d.example"], "x", None)
  let cmds = sent_lines(f)
  assert_eq(cmds[4], "lf line\r\nsecond\r\n")
}

///|
async test "smtp: 5xx at MAIL FROM raises with the server text" {
  let f = fake_sock(["220 ready", "250 ok", "550 relay denied"])
  let raised = try {
    smtp_send(f, "x\r\n", "a@b.example", ["c@d.example"], "x", None)
    false
  } catch {
    e => {
      let msg = "\{e}"
      msg.contains("550") && msg.contains("relay denied")
    }
  }
  assert_true(raised)
}

///|
async test "smtp: server close mid-conversation raises" {
  let f = fake_sock(["220 ready"])
  let raised = try {
    smtp_send(f, "x\r\n", "a@b.example", ["c@d.example"], "x", None)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
async test "smtp: credentials without server AUTH capability raise" {
  let f = fake_sock(["220 ready", "250-no auth here", "250 done"])
  let raised = try {
    smtp_send(f, "x\r\n", "a@b.example", ["c@d.example"], "x", Some(("u", "p")))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
async test "transport: AUTH refused on non-local plaintext host" {
  let t = SmtpTransport::{
    host: "mail.example.com",
    port: 587,
    ehlo_domain: "x",
    user: Some("u"),
    password: Some("p"),
  }
  let raised = try {
    t.send("m\r\n", "a@b.example", ["c@d.example"])
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // local hosts are allowed to authenticate
  let t2 = SmtpTransport::{
    host: "127.0.0.1",
    port: 1,
    ehlo_domain: "x",
    user: Some("u"),
    password: Some("p"),
  }
  let raised2 = try {
    // port 1 refuses at connect time; the AUTH guard must NOT fire first
    t2.send("m\r\n", "a@b.example", ["c@d.example"])
    false
  } catch {
    e => !e.to_string().contains("refusing AUTH")
  }
  assert_true(raised2)
}

///|
async test "send_over: socket closed exactly once even on protocol error" {
  let f = fake_sock(["220 ready", "250 ok", "550 relay denied"])
  let raised = try {
    send_over(f, "x\r\n", "a@b.example", ["c@d.example"], "x", None)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  assert_eq(f.closes, 1)
}

///|
async test "send_over: socket closed exactly once on success" {
  let f = fake_sock([
    "220 ready", "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  send_over(f, "body\r\n", "a@b.example", ["c@d.example"], "x.example", None)
  assert_eq(f.closes, 1)
}

///|
async test "smtp: multi-line reply with inconsistent codes raises" {
  let f = fake_sock(["220 ready", "250-go", "550 rogue", "250 done"])
  let raised = try {
    smtp_send(f, "x\r\n", "a@b.example", ["c@d.example"], "x", None)
    false
  } catch {
    e => {
      let msg = "\{e}"
      msg.contains("inconsistent")
    }
  }
  assert_true(raised)
}

///|
/// STARTTLS sequencing tests (plan tls-transport M2): the upgrade
/// itself is a FakeSock identity swap — real TLS is proven against the
/// local sink in e2e, not here.

///|
async test "smtp: STARTTLS negotiation sends EHLO then STARTTLS" {
  let f = fake_sock(["220 ready", "250-STARTTLS", "250 done", "220 go ahead"])
  smtp_greeting(f)
  smtp_starttls_ehlo(f, "x.example")
  let cmds = sent_lines(f)
  assert_eq(cmds[0], "EHLO x.example\r\n")
  assert_eq(cmds[1], "STARTTLS\r\n")
}

///|
async test "smtp: STARTTLS refused when capability missing" {
  let f = fake_sock(["220 ready", "250-no tls here", "250 done"])
  let raised = try {
    smtp_greeting(f)
    smtp_starttls_ehlo(f, "x.example")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
async test "smtp: session after upgrade re-runs EHLO first" {
  let f = fake_sock(["220 ready", "250-STARTTLS", "250 done", "220 go ahead"])
  smtp_greeting(f)
  smtp_starttls_ehlo(f, "x.example")
  let g = fake_sock([
    "250 ok", "250 ok", "250 ok", "354 go", "250 stored", "221 bye",
  ])
  smtp_session(g, "hi\r\n", "a@b.example", ["c@d.example"], "x.example", None)
  let cmds = sent_lines(g)
  assert_eq(cmds[0], "EHLO x.example\r\n")
  assert_eq(cmds[1], "MAIL FROM:<a@b.example>\r\n")
  assert_eq(cmds[5], ".\r\n")
}
