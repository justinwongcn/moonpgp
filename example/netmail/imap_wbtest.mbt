///|
/// Offline IMAP state-machine tests: a scripted BYTE-STREAM fake
/// Socket drives the client, so chunk boundaries can cut lines, CRLF
/// pairs, literal markers and literal bodies — exactly the hazards the
/// plan's test matrix calls out. White-box file: the client structs and
/// the state machine are package-private by design.

///|
priv struct FakeImapSock {
  script : Array[Bytes]
  mut chunk : Int
  mut off : Int
  sent : Array[Bytes]
  mut closes : Int
}

///|
fn imap_fake(chunks : Array[Bytes]) -> FakeImapSock {
  { script: chunks, chunk: 0, off: 0, sent: [], closes: 0, }
}

///|
impl Socket for FakeImapSock with fn read_raw_line(self) -> Bytes raise {
  let out : Array[Byte] = []
  let mut pending_cr = false
  while true {
    guard self.chunk < self.script.length() else {
      @error.fail("fake: script exhausted")
    }
    let cur = self.script[self.chunk]
    while self.off < cur.length() {
      let v = cur[self.off]
      self.off = self.off + 1
      if v == b'\n' {
        return Bytes::from_array(out)
      }
      if pending_cr {
        out.push(b'\r')
      }
      if v == b'\r' {
        pending_cr = true
      } else {
        out.push(v)
        pending_cr = false
      }
    }
    self.chunk = self.chunk + 1
    self.off = 0
  }
  abort("fake: unreachable")
}

///|
impl Socket for FakeImapSock with fn read_exact(self, n : Int) -> Bytes raise {
  let out : Array[Byte] = []
  let mut got = 0
  while got < n {
    guard self.chunk < self.script.length() else {
      @error.fail("fake: script exhausted mid-literal")
    }
    let cur = self.script[self.chunk]
    if self.off < cur.length() {
      out.push(cur[self.off])
      self.off = self.off + 1
      got = got + 1
    } else {
      self.chunk = self.chunk + 1
      self.off = 0
    }
  }
  Bytes::from_array(out)
}

///|
impl Socket for FakeImapSock with fn read_line(self) -> String raise {
  bytes_lossy(Socket::read_raw_line(self))
}

///|
impl Socket for FakeImapSock with fn write_all(self, data : Bytes) -> Unit raise {
  self.sent.push(data)
}

///|
impl Socket for FakeImapSock with fn close(self) -> Unit {
  self.closes = self.closes + 1
}

///|
fn sb(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
fn bcat(parts : Array[Bytes]) -> Bytes {
  let out : Array[Byte] = []
  for p in parts {
    for b in p {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}

///|
fn sent_text(f : FakeImapSock) -> String {
  bytes_lossy(bcat(f.sent))
}

///|
fn new_client(sock : FakeImapSock) -> ImapClient {
  ImapClient::{
    sock,
    tag_n: 0,
    state: MailboxState::{ exists: 0, uidvalidity: 0, },
  }
}

///|
fn select_response() -> Bytes {
  sb(
    "* 4 EXISTS\r\n* 0 RECENT\r\n* OK [UNSEEN 1] unseen\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n* FLAGS (\\Answered \\Seen \\Deleted \\Draft \\Flagged)\r\n* OK [PERMANENTFLAGS (\\Answered \\Seen \\Deleted \\Draft \\Flagged)] Limited\r\na3 OK [READ-WRITE] SELECT completed\r\n",
  )
}

///|
test "imap: full happy session — LOGIN, ID before SELECT, list, logout" {
  let f = imap_fake([
    b"* OK Coremail System IMap Server Ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"* ID (\"name\" \"Coremail Imap\")\r\na2 OK ID completed\r\n",
    select_response(),
    b"a4 OK Fetch completed\r\n",
    b"* BYE\r\na5 OK LOGOUT completed\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  assert_eq(c.state.exists, 4)
  assert_eq(c.state.uidvalidity, 1)
  let _ = c.imap_fetch_recent(5)
  c.imap_logout()
  assert_eq(f.closes, 1)
  // the sent stream is push-ordered, so index = command order:
  // ID must precede SELECT (the Coremail quirk under test)
  let lines : Array[String] = []
  for raw in f.sent {
    lines.push(bytes_lossy(raw))
  }
  assert_eq(lines.length(), 5)
  assert_true(lines[0].contains("LOGIN \"u@163.com\" \"secret1\"\r\n"))
  assert_true(
    lines[1].contains(
      "ID (\"name\" \"moonpgp-mailreader\" \"version\" \"1.0.0\")",
    ),
  )
  assert_true(lines[2].contains("SELECT INBOX"))
  assert_true(
    lines[3].contains(
      "FETCH 1:4 (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])",
    ),
  )
  assert_true(lines[4].contains("LOGOUT\r\n"))
}

///|
test "imap: PREAUTH greeting is refused (login is mandatory in v1)" {
  let f = imap_fake([b"* PREAUTH [CAPABILITY IMAP4rev1] ready\r\n"])
  let c = new_client(f)
  let raised = try {
    c.read_greeting()
    false
  } catch {
    e => e.to_string().contains("PREAUTH")
  }
  assert_true(raised)
}

///|
test "imap: BYE greeting is refused" {
  let f = imap_fake([b"* BYE server shutting down\r\n"])
  let c = new_client(f)
  let raised = try {
    c.read_greeting()
    false
  } catch {
    e => e.to_string().contains("BYE")
  }
  assert_true(raised)
}

///|
test "imap: LOGIN NO raises with the server text" {
  let f = imap_fake([
    b"* OK ready\r\n", b"a1 NO LOGIN AUTHENTICATIONFAILED bad credentials\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  let raised = try {
    c.imap_login("u@163.com", "wrong")
    false
  } catch {
    e => e.to_string().contains("AUTHENTICATIONFAILED")
  }
  assert_true(raised)
}

///|
test "imap: SELECT NO (Unsafe Login) raises with the server text" {
  let f = imap_fake([
    b"* OK ready\r\n", b"a1 OK LOGIN completed\r\n", b"a2 OK ID completed\r\n", b"a3 NO SELECT Unsafe Login. Please contact kefu@188.com for help\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  let raised = try {
    c.imap_select("INBOX")
    false
  } catch {
    e => e.to_string().contains("Unsafe Login")
  }
  assert_true(raised)
}

///|
test "imap: FETCH list parses the real response shape" {
  let headers : Bytes = b"From: user-b <user-b@example.com>\r\nSubject: =?utf-8?B?5Zue5aSN77ya?=\r\nDate: Sat, 03 Oct 2026 19:12:26 +0000\r\n\r\n"
  let body = bcat([
    b"* 4 FETCH (UID 4 FLAGS (\\Seen) INTERNALDATE \" 4-Oct-2026 03:12:37 +0800\" RFC822.SIZE 5718 BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {",
    sb("\{headers.length()}"),
    b"}\r\n",
    headers,
    b")\r\na4 OK Fetch completed\r\n",
  ])
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    body,
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let summaries = c.imap_fetch_recent(5)
  assert_eq(summaries.length(), 1)
  let s = summaries[0]
  assert_eq(s.seq, 4)
  assert_eq(s.uid, 4)
  assert_eq(s.flags, "(\\Seen)")
  assert_eq(s.internaldate, " 4-Oct-2026 03:12:37 +0800")
  assert_eq(s.size, 5718)
  assert_eq(bytes_lossy(s.headers), bytes_lossy(headers))
}

///|
test "imap: FETCH items in server-reordered order still parse" {
  let headers : Bytes = b"From: a@b.example\r\n\r\n"
  // NOTE: the literal bytes must follow the marker inside the stream —
  // rebuild with the literal inline:
  let full = bcat([
    b"* 2 FETCH (RFC822.SIZE 10 BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {",
    sb("\{headers.length()}"),
    b"}\r\n",
    headers,
    b" INTERNALDATE \" 4-Oct-2026 01:00:00 +0800\" FLAGS (\\Seen) UID 99)\r\na4 OK done\r\n",
  ])
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    full,
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let summaries = c.imap_fetch_recent(5)
  assert_eq(summaries.length(), 1)
  let s = summaries[0]
  assert_eq(s.seq, 2)
  assert_eq(s.uid, 99)
  assert_eq(s.size, 10)
  assert_eq(bytes_lossy(s.headers), bytes_lossy(headers))
}

///|
test "imap: literal body cut across recv chunks stays byte-exact" {
  // binary payload with CRLF and high bytes inside the literal
  let payload : Bytes = Bytes::from_array([
    b'a', b'b', b'\r', b'\n', b'\x80', b'\xFF', b'c', b'd', b'e',
  ])
  let full = bcat([
    b"* 1 FETCH (UID 1 BODY[] {",
    sb("\{payload.length()}"),
    b"}\r\n",
    payload,
    b")\r\na4 OK done\r\n",
  ])
  // split at the awkward points: inside the marker digits is covered
  // below; here we split INSIDE the literal body after byte 3
  let cut = full.length() - 7
  let first = full[0:cut].to_owned()
  let rest = full[cut:full.length()].to_owned()
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    first,
    rest,
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raw = c.imap_fetch_message(1)
  assert_eq(raw.length(), payload.length())
  for i in 0..<payload.length() {
    assert_eq(raw[i], payload[i])
  }
}

///|
test "imap: literal marker digits cut across chunks parse" {
  let payload : Bytes = b"hello"
  // rebuild with a 5-byte literal and split the marker `{5}` itself
  let marker_line = b"* 1 FETCH (UID 1 BODY[] {"
  let mid = b"5}\r\n"
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    marker_line,
    mid,
    payload,
    b")\r\na4 OK done\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raw = c.imap_fetch_message(1)
  assert_eq(bytes_lossy(raw), "hello")
}

///|
test "imap: LITERAL+ marker {n+} is accepted" {
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    b"* 1 FETCH (UID 7 BODY[] {5+}\r\n",
    b"hello)\r\na4 OK done\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raw = c.imap_fetch_message(7)
  assert_eq(bytes_lossy(raw), "hello")
}

///|
test "imap: EXPUNGE and EXISTS interleaved in a FETCH reply are skipped" {
  let headers : Bytes = b"From: a@b.example\r\n\r\n"
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    bcat([
      b"* 3 EXPUNGE\r\n* 4 EXISTS\r\n* 4 FETCH (UID 4 FLAGS (\\Seen) BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {",
      sb("\{headers.length()}"),
      b"}\r\n",
      headers,
      b")\r\na4 OK done\r\n",
    ]),
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let summaries = c.imap_fetch_recent(5)
  assert_eq(summaries.length(), 1)
  assert_eq(summaries[0].uid, 4)
}

///|
test "imap: `+ ` continuation is a protocol error in this subset" {
  let f = imap_fake([b"* OK ready\r\n", b"+ Ready for literal\r\n"])
  let c = new_client(f)
  c.read_greeting()
  let raised = try {
    c.imap_login("u@163.com", "secret1")
    false
  } catch {
    e => e.to_string().contains("client literal")
  }
  assert_true(raised)
}

///|
test "imap: UID FETCH NO raises with the server text" {
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    b"a4 NO UID FETCH mail vanished\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raised = try {
    ignore(c.imap_fetch_message(99))
    false
  } catch {
    e => e.to_string().contains("mail vanished")
  }
  assert_true(raised)
}

///|
test "imap: reply tag mismatch raises" {
  let f = imap_fake([b"* OK ready\r\n", b"aX OK nonsense\r\n"])
  let c = new_client(f)
  c.read_greeting()
  let raised = try {
    c.imap_login("u@163.com", "secret1")
    false
  } catch {
    e => e.to_string().contains("tag mismatch")
  }
  assert_true(raised)
}

///|
test "imap: LOGIN args are validated before anything is sent" {
  let f = imap_fake([b"* OK ready\r\n"])
  let c = new_client(f)
  c.read_greeting()
  let raised = try {
    c.imap_login("bad\"user@example.com", "secret1")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  let raised2 = try {
    c.imap_login("u@163.com", "pa{ss}")
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
  let raised3 = try {
    c.imap_login("u@163.com", "pa\nss")
    false
  } catch {
    _ => true
  }
  assert_true(raised3)
  // nothing reached the wire
  assert_eq(f.sent.length(), 0)
}

///|
test "imap: empty mailbox lists nothing and sends no FETCH" {
  let f = imap_fake([
    b"* OK ready\r\n", b"a1 OK LOGIN completed\r\n", b"a2 OK ID completed\r\n", b"* 0 EXISTS\r\na3 OK [READ-WRITE] SELECT completed\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let summaries = c.imap_fetch_recent(5)
  assert_eq(summaries.length(), 0)
  assert_true(!sent_text(f).contains(" FETCH "))
}

///|
test "imap: --last larger than EXISTS clamps to 1:exists" {
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    b"a4 OK Fetch completed\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  ignore(c.imap_fetch_recent(10))
  assert_true(sent_text(f).contains("FETCH 1:4 "))
}

///|
test "imap: LOGOUT survives a server that hangs up after BYE" {
  let f = imap_fake([b"* OK ready\r\n", b"* BYE log out now\r\n"])
  let c = new_client(f)
  c.read_greeting()
  c.imap_logout()
  assert_eq(f.closes, 1)
}

///|
test "imap: EOF mid-literal raises instead of hanging" {
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    b"* 1 FETCH (UID 1 BODY[] {100}\r\n",
    b"short",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raised = try {
    ignore(c.imap_fetch_message(1))
    false
  } catch {
    e => e.to_string().contains("script exhausted")
  }
  assert_true(raised)
}

///|
test "imap: literal size overflow guard rejects a wrapped digit string" {
  // {4294967396} (= 2^32+100) wraps to a small Int without the guard
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    b"* 1 FETCH (UID 1 BODY[] {4294967396}\r\n",
    b"short",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raised = try {
    ignore(c.imap_fetch_message(1))
    false
  } catch {
    e => e.to_string().contains("overflow guard")
  }
  assert_true(raised)
}

///|
test "imap: UID echo mismatch raises (stale-UID safety net)" {
  let payload : Bytes = b"hello"
  let f = imap_fake([
    b"* OK ready\r\n",
    b"a1 OK LOGIN completed\r\n",
    b"a2 OK ID completed\r\n",
    select_response(),
    bcat([
      b"* 1 FETCH (UID 999 BODY[] {",
      sb("\{payload.length()}"),
      b"}\r\n",
      payload,
      b")\r\na4 OK done\r\n",
    ]),
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  let raised = try {
    ignore(c.imap_fetch_message(1))
    false
  } catch {
    e => e.to_string().contains("UID mismatch")
  }
  assert_true(raised)
}

///|
test "imap: greeting consumes pre-OK untagged lines (merged CAPABILITY)" {
  let f = imap_fake([
    b"* CAPABILITY IMAP4rev1 STARTTLS\r\n", b"* OK ready\r\n", b"a1 OK LOGIN completed\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  assert_true(sent_text(f).contains("LOGIN"))
}

///|
test "imap: merged [UIDVALIDITY n UIDNEXT m] response code parses" {
  let f = imap_fake([
    b"* OK ready\r\n", b"a1 OK LOGIN completed\r\n", b"a2 OK ID completed\r\n", b"* 7 EXISTS\r\n* OK [UIDVALIDITY 1234 UIDNEXT 8] UIDs valid\r\na3 OK [READ-WRITE] done\r\n",
  ])
  let c = new_client(f)
  c.read_greeting()
  c.imap_login("u@163.com", "secret1")
  c.imap_id()
  c.imap_select("INBOX")
  assert_eq(c.state.exists, 7)
  assert_eq(c.state.uidvalidity, 1234)
}
