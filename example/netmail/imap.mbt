///|
/// IMAP4rev1 client state machine (RFC 3501 submission subset:
/// LOGIN → ID → SELECT → FETCH → LOGOUT) over the mailnet Socket seam,
/// so the full protocol behavior is testable offline against a
/// scripted byte-stream fake. Design points from the plan approval
/// round (docs/mail-fetch-plan.md §4.2/§5):
/// - literals are read byte-faithfully (mailnet read_exact) and cut
///   out of the line BEFORE token scanning, so arbitrary octets in a
///   message never reach the syntax parser;
/// - the response item scanner is quote/paren aware: INTERNALDATE is a
///   quoted string with spaces, FLAGS is a paren list, and the section
///   atom `BODY[HEADER.FIELDS (FROM SUBJECT DATE)]` is one token;
/// - Coremail requires the ID command before SELECT (else
///   "Unsafe Login");
/// - cross-session addressing uses UID only (sequence numbers shift on
///   EXPUNGE between sessions).

///|
/// One segment of a logical response line: inline syntax text, or the
/// raw bytes of an inline literal.
priv enum Seg {
  Txt(Bytes)
  Lit(Bytes)
}

///|
/// Parsed response tokens. `Atom` covers numbers, keywords and
/// bracketed sections; `Raw` is a literal delivered at this position.
priv enum Node {
  Atom(String)
  Quoted(String)
  Parens(Array[Node])
  Raw(Bytes)
}

///|
/// Everything this client needs from one SELECT: message count and the
/// mailbox UIDVALIDITY as advertised by the server. NOTE (v1 honesty):
/// UIDVALIDITY is REPORTED, not persisted-compared across sessions —
/// the stale-UID safety net is the UID echo check in imap_fetch_message.
pub(all) struct MailboxState {
  mut exists : Int
  mut uidvalidity : Int
}

///|
/// One summarized message from the list fetch.
pub(all) struct MailSummary {
  seq : Int
  uid : Int
  flags : String
  internaldate : String
  size : Int
  /// Raw bytes of the requested header-fields block (a literal).
  headers : Bytes
}

///|
pub(all) struct ImapClient {
  sock : &Socket
  mut tag_n : Int
  state : MailboxState
}

///|
/// Read one logical response line: a raw line, plus (while the text
/// tail ends with a `{n}` / `{n+}` marker) the exact literal and the
/// continuation text. The marker itself is framing and is stripped
/// from the text segment, exactly like the CRLF.
fn read_logical_line(sock : &Socket) -> Array[Seg] raise {
  let segs : Array[Seg] = []
  while true {
    let raw = sock.read_raw_line()
    let size = literal_marker_size(raw)
    if size >= 0 {
      let cut = marker_cut_index(raw)
      segs.push(Seg::Txt(raw[0:cut].to_owned()))
      segs.push(Seg::Lit(sock.read_exact(size)))
      continue
    }
    segs.push(Seg::Txt(raw))
    return segs
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
/// Literal size when the line ends with `{n}` or `{n+}`, else -1.
fn literal_marker_size(b : Bytes) -> Int raise {
  let n = b.length()
  guard n >= 3 else { return -1 }
  guard b[n - 1] == b'}' else { return -1 }
  let mut k = n - 2
  // optional LITERAL+ suffix: {5+}
  if b[k] == b'+' {
    k = k - 1
  }
  let digits_end = k
  while k >= 1 && b[k] >= b'0' && b[k] <= b'9' {
    k = k - 1
  }
  guard k >= 0 && b[k] == b'{' && digits_end > k else { return -1 }
  // sanity: a syntax-text `{digits}` is only ever server framing; a
  // huge value means we misread the stream — refuse instead of trying
  // to read_exact it. The accumulation is overflow-checked: a 2^32+k
  // digit string wraps to a small Int and would sneak past a plain
  // post-hoc bound (review finding m1).
  let max_literal = 100_000_000
  let start = k + 1
  let stop = digits_end + 1
  let mut v = 0
  for i in start..<stop {
    let d = b[i].to_int() - 48
    if v > (max_literal - d) / 10 {
      @error.fail("mailreader: implausible literal size (overflow guard)")
    }
    v = v * 10 + d
  }
  v
}

///|
/// Index of the `{` opening the trailing literal marker.
fn marker_cut_index(b : Bytes) -> Int {
  let n = b.length()
  let mut k = n - 2
  if b[k] == b'+' {
    k = k - 1
  }
  while k >= 1 && b[k] >= b'0' && b[k] <= b'9' {
    k = k - 1
  }
  k
}

///|
/// Quote/paren-aware scanner: Segs → top-level Nodes. `[...]` sections
/// bind to the current atom and swallow their whole content (no nested
/// sections exist in the subset), quoted strings honor `\\` escapes,
/// and a Lit segment becomes a Raw node at its position.
fn parse_nodes(segs : Array[Seg]) -> Array[Node] raise {
  let out : Array[Node] = []
  let mut si = 0
  let mut bi = 0
  while si < segs.length() {
    match segs[si] {
      Lit(data) => {
        out.push(Node::Raw(data))
        si = si + 1
        bi = 0
      }
      Txt(text) => {
        if bi >= text.length() {
          si = si + 1
          bi = 0
          continue
        }
        let c = text[bi]
        if c == b' ' {
          bi = bi + 1
          continue
        }
        if c == b'"' {
          let (q, nbi) = scan_quoted(text, bi + 1)
          out.push(Node::Quoted(q))
          bi = nbi
          continue
        }
        if c == b'(' {
          let (items, ni, nbi) = scan_parens(segs, si, bi + 1)
          out.push(Node::Parens(items))
          si = ni
          bi = nbi
          continue
        }
        let (atom, ni, nbi) = scan_atom(segs, si, bi)
        out.push(Node::Atom(atom))
        si = ni
        bi = nbi
      }
    }
  }
  out
}

///|
fn scan_quoted(text : Bytes, start : Int) -> (String, Int) raise {
  let sb = StringBuilder()
  let mut i = start
  while i < text.length() {
    let c = text[i]
    if c == b'\\' && i + 1 < text.length() {
      sb.write_char(byte_to_char(text[i + 1]))
      i = i + 2
      continue
    }
    if c == b'"' {
      return (sb.to_string(), i + 1)
    }
    sb.write_char(byte_to_char(c))
    i = i + 1
  }
  @error.fail("mailreader: unterminated quoted string")
}

///|
fn scan_parens(
  segs : Array[Seg],
  si : Int,
  bi : Int,
) -> (Array[Node], Int, Int) raise {
  let items : Array[Node] = []
  let mut s = si
  let mut b = bi
  while true {
    guard s < segs.length() else {
      @error.fail("mailreader: unterminated list")
    }
    match segs[s] {
      Lit(data) => {
        items.push(Node::Raw(data))
        s = s + 1
        b = 0
      }
      Txt(text) => {
        if b >= text.length() {
          s = s + 1
          b = 0
          continue
        }
        let c = text[b]
        if c == b' ' {
          b = b + 1
          continue
        }
        if c == b')' {
          return (items, s, b + 1)
        }
        if c == b'(' {
          let (inner, ns, nb) = scan_parens(segs, s, b + 1)
          items.push(Node::Parens(inner))
          s = ns
          b = nb
          continue
        }
        if c == b'"' {
          let (q, nb) = scan_quoted(text, b + 1)
          items.push(Node::Quoted(q))
          b = nb
          continue
        }
        let (atom, ns, nb) = scan_atom(segs, s, b)
        items.push(Node::Atom(atom))
        s = ns
        b = nb
      }
    }
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
/// One atom: runs of non-space/non-delim bytes; a `[` section binds to
/// the atom and consumes through the matching `]` (spaces and parens
/// inside a section are part of it).
fn scan_atom(segs : Array[Seg], si : Int, bi : Int) -> (String, Int, Int) raise {
  let sb = StringBuilder()
  let mut s = si
  let mut b = bi
  while true {
    guard s < segs.length() else { return (sb.to_string(), s, b) }
    match segs[s] {
      Lit(_) =>
        // a literal directly after an atom terminates the atom
        return (sb.to_string(), s, b)
      Txt(text) => {
        if b >= text.length() {
          s = s + 1
          b = 0
          continue
        }
        let c = text[b]
        if c == b' ' || c == b'(' || c == b')' || c == b'"' {
          return (sb.to_string(), s, b)
        }
        if c == b'[' {
          // section: swallow through the matching ']'
          sb.write_char('[')
          b = b + 1
          let mut depth = 1
          let mut closed = false
          while s < segs.length() && !closed {
            match segs[s] {
              Lit(_) =>
                // sections never contain literals; treat as end
                break
              Txt(t) => {
                while b < t.length() {
                  let d = t[b]
                  b = b + 1
                  sb.write_char(byte_to_char(d))
                  if d == b']' {
                    depth = depth - 1
                    if depth == 0 {
                      closed = true
                      break
                    }
                  }
                }
                if !closed {
                  s = s + 1
                  b = 0
                }
              }
            }
          }
          guard closed else {
            @error.fail("mailreader: unterminated section atom")
          }
          continue
        }
        sb.write_char(byte_to_char(c))
        b = b + 1
      }
    }
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
fn node_text(node : Node) -> String {
  match node {
    Atom(s) => s
    Quoted(s) => "\{s}"
    Parens(items) => {
      let parts : Array[String] = []
      for it in items {
        parts.push(node_text(it))
      }
      "(\{parts.join(" ")})"
    }
    Raw(data) => bytes_lossy(data)
  }
}

///|
pub fn bytes_lossy(data : Bytes) -> String {
  let sb = StringBuilder()
  for b in data {
    match b.to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => sb.write_char('?')
    }
  }
  sb.to_string()
}

///|
/// Lossy char helper shared by the scanners: invalid scalars become '?'.
fn byte_to_char(b : Byte) -> Char {
  match b.to_int().to_char() {
    Some(c) => c
    None => '?'
  }
}

///|
/// One reply: the tagged status plus every untagged line that preceded
/// it (each without the leading `*` node). NO/BAD raise with the
/// server text; a best-effort LOGOUT is the caller's job (errdefer at
/// the connection wrapper).
priv struct ImapReply {
  untagged : Array[Array[Node]]
  status : String
  text : String
}

///|
fn ImapClient::next_tag(self : ImapClient) -> String {
  self.tag_n = self.tag_n + 1
  "a\{self.tag_n}"
}

///|
fn ImapClient::send_command(self : ImapClient, line : String) -> String raise {
  let tag = self.next_tag()
  self.sock.write_all(@utf8.encode("\{tag} \{line}\r\n"))
  tag
}

///|
/// Read replies until the line tagged `tag` arrives. Untagged lines
/// are collected in order. The special `+ ` continuation cannot occur
/// in this subset (the client never sends literals) and is rejected.
fn ImapClient::read_reply(self : ImapClient, tag : String) -> ImapReply raise {
  let untagged : Array[Array[Node]] = []
  while true {
    let nodes = parse_nodes(read_logical_line(self.sock))
    guard nodes.length() >= 1 else { continue }
    match nodes[0] {
      Atom("*") => {
        guard nodes.length() >= 2 else { continue }
        untagged.push(nodes[1:nodes.length()].to_owned())
        continue
      }
      Atom("+") =>
        // `+ ` demands a client literal; this subset never sends one
        @error.fail(
          "mailreader: server demanded a client literal (not supported)",
        )
      Atom(t) => {
        guard t == tag else {
          @error.fail("mailreader: reply tag mismatch (\{t} vs \{tag})")
        }
        guard nodes.length() >= 2 else {
          @error.fail("mailreader: malformed tagged reply")
        }
        match nodes[1] {
          Atom(status) => {
            let text_parts : Array[String] = []
            for i in 2..<nodes.length() {
              text_parts.push(node_text(nodes[i]))
            }
            return ImapReply::{ untagged, status, text: text_parts.join(" "), }
          }
          _ => @error.fail("mailreader: malformed tagged reply")
        }
      }
      _ => @error.fail("mailreader: response line does not start with a tag")
    }
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
fn ImapClient::expect_ok(
  self : ImapClient,
  tag : String,
  what : String,
) -> ImapReply raise {
  let reply = self.read_reply(tag)
  guard reply.status == "OK" else {
    @error.fail("mailreader: \{what} failed (\{reply.status}): \{reply.text}")
  }
  reply
}

///|
/// Read the greeting: consume the untagged stream (servers may send
/// `* CAPABILITY ...` first) until the `* OK` completion; PREAUTH would
/// skip the login this client must perform and BYE means no session.
pub fn ImapClient::read_greeting(self : ImapClient) -> Unit raise {
  while true {
    let nodes = parse_nodes(read_logical_line(self.sock))
    guard nodes.length() >= 2 else {
      @error.fail("mailreader: malformed greeting")
    }
    match (nodes[0], nodes[1]) {
      (Atom("*"), Atom(word)) => {
        if word == "OK" {
          return
        }
        guard word == "CAPABILITY" || word == "ALERT" else {
          @error.fail("mailreader: unexpected greeting (* \{word})")
        }
        // pre-OK untagged lines (e.g. * CAPABILITY): keep consuming
      }
      _ => @error.fail("mailreader: malformed greeting")
    }
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
pub fn connect_imap(
  host : String,
  port : Int,
  allow_insecure : Bool,
) -> ImapClient raise {
  if !is_local_host(host) && !allow_insecure {
    @error.fail(
      "mailreader: refusing plaintext LOGIN to non-local host '\{host}' (no TLS; tunnel via stunnel to port 993, or pass --allow-insecure)",
    )
  }
  let sock = connect_socket(host, port)
  let client = ImapClient::{
    sock,
    tag_n: 0,
    state: MailboxState::{ exists: 0, uidvalidity: 0, },
  }
  errdefer sock.close()
  client.read_greeting()
  client
}

///|
/// LOGIN arguments are quoted strings; restrict them to printable
/// ASCII without the quoted-specials `"` `\` and the literal opener
/// `{` so no argument can reshape the command (CTLs excluded too).
fn validate_login_arg(value : String, what : String) -> Unit raise {
  guard value.length() > 0 else {
    @error.fail("mailreader: empty LOGIN \{what}")
  }
  for c in value {
    let v = c.to_int()
    guard v >= 0x20 && v <= 0x7E && c != '"' && c != '\\' && c != '{' else {
      @error.fail("mailreader: LOGIN \{what} contains a forbidden character")
    }
  }
}

///|
pub fn ImapClient::imap_login(
  self : ImapClient,
  user : String,
  password : String,
) -> Unit raise {
  validate_login_arg(user, "user")
  validate_login_arg(password, "password")
  let tag = self.send_command("LOGIN \"\{user}\" \"\{password}\"")
  ignore(self.expect_ok(tag, "LOGIN"))
}

///|
/// Coremail requires this before SELECT ("Unsafe Login" otherwise).
pub fn ImapClient::imap_id(self : ImapClient) -> Unit raise {
  let tag = self.send_command(
    "ID (\"name\" \"moonpgp-mailreader\" \"version\" \"1.0.0\")",
  )
  ignore(self.expect_ok(tag, "ID"))
}

///|
pub fn ImapClient::imap_select(
  self : ImapClient,
  folder : String,
) -> Unit raise {
  let tag = self.send_command("SELECT \{folder}")
  let reply = self.expect_ok(tag, "SELECT")
  for line in reply.untagged {
    match line.length() {
      2 =>
        match (line[0], line[1]) {
          (Atom(n), Atom(word)) =>
            if word == "EXISTS" {
              match parse_int(n) {
                Some(v) => self.state.exists = v
                None => ()
              }
            }
          _ => ()
        }
      _ => ()
    }
    // `* OK [UIDVALIDITY v] ...`; both the single-code and the merged
    // `[UIDVALIDITY n UIDNEXT m]` forms occur in the wild
    if line.length() >= 2 {
      match line[1] {
        Atom(code) =>
          if code.has_prefix("[UIDVALIDITY ") && code.has_suffix("]") {
            let inner = code[13:code.length() - 1].to_owned()
            let tokens = inner.split(" ").collect()
            if tokens.length() >= 1 {
              match parse_int(tokens[0].to_owned()) {
                Some(v) => self.state.uidvalidity = v
                None => ()
              }
            }
          }
        _ => ()
      }
    }
  }
}

///|
pub fn parse_int(s : String) -> Int? {
  guard s.length() > 0 else { return None }
  let mut v = 0
  for c in s {
    let d = c.to_int() - 48
    guard d >= 0 && d <= 9 else { return None }
    // Int overflow wraps silently; a wrapped EXISTS/UID/size would be
    // silently misparsed (review finding m1)
    if v > (2147483647 - d) / 10 {
      return None
    }
    v = v * 10 + d
  }
  Some(v)
}

///|
/// `FETCH first:last (UID FLAGS INTERNALDATE RFC822.SIZE
/// BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])` with the review
/// bounds: clamp to >= 1 and skip the command entirely on an empty
/// mailbox.
pub fn ImapClient::imap_fetch_recent(
  self : ImapClient,
  last_n : Int,
) -> Array[MailSummary] raise {
  let exists = self.state.exists
  guard exists > 0 else { return [] }
  let last = if last_n > exists { exists } else { last_n }
  let first = exists - last + 1
  let first = if first < 1 { 1 } else { first }
  let tag = self.send_command(
    "FETCH \{first}:\{exists} (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])",
  )
  let reply = self.expect_ok(tag, "FETCH list")
  let out : Array[MailSummary] = []
  for line in reply.untagged {
    match parse_fetch_items(line) {
      Some((seq, items)) =>
        match summary_from_items(seq, items) {
          Some(s) => out.push(s)
          None => ()
        }
      None => ()
    }
  }
  out
}

///|
/// `UID FETCH <uid> (BODY.PEEK[])` → the full raw message bytes. The
/// response's UID echo must equal the requested uid: sequence numbers
/// shift across sessions, so the echo is the check that we are
/// decrypting the message the user actually pointed at.
pub fn ImapClient::imap_fetch_message(
  self : ImapClient,
  uid : Int,
) -> Bytes raise {
  let tag = self.send_command("UID FETCH \{uid} (BODY.PEEK[])")
  let reply = self.expect_ok(tag, "UID FETCH")
  for line in reply.untagged {
    match parse_fetch_items(line) {
      Some((_seq, items)) => {
        let mut echoed_uid = -1
        let mut body : Bytes? = None
        for k in 0..<items.length() {
          match items[k] {
            Atom(name) => {
              if name == "UID" && k + 1 < items.length() {
                match items[k + 1] {
                  Atom(v) =>
                    match parse_int(v) {
                      Some(v) => echoed_uid = v
                      None => ()
                    }
                  _ => ()
                }
              }
              if name.has_prefix("BODY[") &&
                body is None &&
                k + 1 < items.length() {
                match items[k + 1] {
                  Raw(data) => body = Some(data)
                  _ => ()
                }
              }
            }
            _ => ()
          }
        }
        guard echoed_uid == uid else {
          @error.fail(
            "mailreader: UID mismatch (requested \{uid}, server echoed \{echoed_uid}); the mailbox changed — re-list before fetching",
          )
        }
        match body {
          Some(data) => return data
          None => ()
        }
      }
      None => ()
    }
  }
  @error.fail(
    "mailreader: UID \{uid} fetch returned no body (or mail vanished)",
  )
}

///|
/// `* <seq> FETCH ( ... )` → (seq, items); other untagged lines → None.
fn parse_fetch_items(line : Array[Node]) -> (Int, Array[Node])? {
  guard line.length() == 3 else { return None }
  let seq = match line[0] {
    Atom(n) => parse_int(n)
    _ => None
  }
  let seq = match seq {
    Some(v) => v
    None => return None
  }
  match line[1] {
    Atom(word) => if word != "FETCH" { return None }
    _ => return None
  }
  match line[2] {
    Parens(items) => Some((seq, items))
    _ => None
  }
}

///|
fn summary_from_items(seq : Int, items : Array[Node]) -> MailSummary? {
  let mut uid = -1
  let mut flags = ""
  let mut internaldate = ""
  let mut size = -1
  let mut headers : Bytes = b""
  let mut k = 0
  while k < items.length() {
    match items[k] {
      Atom(name) => {
        let value : Node? = if k + 1 < items.length() {
          Some(items[k + 1])
        } else {
          None
        }
        if name == "UID" {
          match value {
            Some(Atom(v)) =>
              match parse_int(v) {
                Some(v) => uid = v
                None => ()
              }
            _ => ()
          }
        } else if name == "FLAGS" {
          match value {
            Some(Parens(_)) => flags = node_text(items[k + 1])
            _ => ()
          }
        } else if name == "INTERNALDATE" {
          match value {
            Some(Quoted(v)) => internaldate = v
            _ => ()
          }
        } else if name == "RFC822.SIZE" {
          match value {
            Some(Atom(v)) =>
              match parse_int(v) {
                Some(v) => size = v
                None => ()
              }
            _ => ()
          }
        } else if name.has_prefix("BODY[") {
          match value {
            Some(Raw(data)) => headers = data
            _ => ()
          }
        }
        // skip the value we just consumed
        if value is Some(_) {
          k = k + 1
        }
      }
      _ => ()
    }
    k = k + 1
  }
  if uid < 0 {
    return None
  }
  Some(MailSummary::{ seq, uid, flags, internaldate, size, headers, })
}

///|
/// LOGOUT then close, swallowing every error: a failed farewell must
/// not mask the session's earlier outcome (Coremail caps concurrent
/// sessions, so the polite path matters). Errors here still close.
pub fn ImapClient::imap_logout(self : ImapClient) -> Unit {
  try {
    let tag = self.send_command("LOGOUT")
    ignore(self.expect_ok(tag, "LOGOUT"))
  } catch {
    _ => ()
  }
  self.sock.close()
}

///|
/// Run `body` with a connected+authenticated session over `folder`.
/// The error path best-effort LOGOUTs (swallowing its own errors,
/// closing included) so Coremail's concurrent-session cap is not
/// tripped by abandoned sessions; imap_logout closes the socket too.
pub fn with_imap_session(
  host : String,
  port : Int,
  allow_insecure : Bool,
  user : String,
  password : String,
  folder : String,
  body : (ImapClient) -> Unit raise,
) -> Unit raise {
  let client = connect_imap(host, port, allow_insecure)
  errdefer client.imap_logout()
  client.imap_login(user, password)
  client.imap_id()
  client.imap_select(folder)
  body(client)
  client.imap_logout()
}

///|
/// Render the gopenpgp four-state signature statuses collected by
/// decrypt_mime as a bracketed list, e.g. "[Ok]" — shared by both
/// example CLIs.
pub fn status_names(status : Array[@api.VerifyStatus]) -> String {
  let parts : Array[String] = []
  for s in status {
    parts.push(
      match s {
        @api.Ok => "Ok"
        @api.NotSigned => "NotSigned"
        @api.NoVerifier => "NoVerifier"
        @api.Failed => "Failed"
      },
    )
  }
  "[\{parts.join(", ")}]"
}
