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
