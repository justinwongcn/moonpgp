///|
/// `FETCH first:last (UID FLAGS INTERNALDATE RFC822.SIZE
/// BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])` with the review
/// bounds: clamp to >= 1 and skip the command entirely on an empty
/// mailbox.
pub fn ImapClient::imap_fetch_recent(
  self : ImapClient,
  last_n : Int32,
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
  uid : Int32,
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
fn parse_fetch_items(line : Array[Node]) -> (Int32, Array[Node])? {
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
fn summary_from_items(seq : Int32, items : Array[Node]) -> MailSummary? {
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
