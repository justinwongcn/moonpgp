///|
/// SMTP client state machine (RFC 5321 minimal submission set). The
/// machine programs against the Socket seam from example/mailnet, so
/// every protocol behavior is testable offline against a scripted
/// fake; the native socket backend supplies the real transport.
/// Protocol rules follow the verbatim-checked table in HANDOFF §8.3.

///|
/// RFC 5321 §4.5.2 dot-stuffing: prepend a '.' to every line that
/// starts with one — the first character of the message included —
/// and guarantee CRLF termination before the terminating ".".
/// Package-internal: exercised through smtp_send in the wbtests.
fn dot_stuff(message : String) -> String {
  let normalized = message
    .replace_all(old="\r\n", new="\n")
    .replace_all(old="\n", new="\r\n")
  let lines : Array[StringView] = normalized.split("\r\n").collect()
  let sb = StringBuilder()
  for i, line in lines {
    if line.has_prefix(".") {
      sb.write_char('.')
    }
    sb.write_stringview(line)
    if i < lines.length() - 1 {
      sb.write_string("\r\n")
    }
  }
  let s = sb.to_string()
  if s.has_suffix("\r\n") {
    s
  } else {
    s + "\r\n"
  }
}

///|
/// Read one (possibly multi-line) reply; the loop consumes "NNN-"
/// continuations until the "NNN " final line, requiring the same code
/// on every line (RFC 5321 §4.2). String supports direct `s[i]`
/// indexing (returns the code unit as Int), so no helper is needed.
fn reply_code(line : String) -> Int raise {
  guard line.length() >= 3 else { @error.fail("smtp: short reply '\{line}'") }
  let mut code = 0
  for k in 0..<3 {
    let v = line[k].to_int() - 48
    guard v >= 0 && v <= 9 else {
      @error.fail("smtp: malformed reply '\{line}'")
    }
    code = code * 10 + v
  }
  code
}

///|
async fn read_reply(sock : &Sock) -> (Int, Array[String]) {
  let first = sock.read_line()
  let code = reply_code(first)
  let lines : Array[String] = []
  let mut line = first
  while line.length() >= 4 && line[3] == '-' {
    lines.push(line[4:].to_owned())
    line = sock.read_line()
    let cont = reply_code(line)
    guard cont == code else {
      @error.fail("smtp: inconsistent multi-line reply (\{code} vs \{cont})")
    }
  }
  if line.length() >= 4 {
    lines.push(line[4:].to_owned())
  } else {
    lines.push("")
  }
  (code, lines)
}

///|
async fn smtp_command(sock : &Sock, line : String) -> Unit {
  sock.write_all(@utf8.encode(line + "\r\n"))
}

///|
async fn expect(
  sock : &Sock,
  want : Int,
  what : String,
) -> (Int, Array[String]) {
  let (code, lines) = read_reply(sock)
  guard code == want else {
    @error.fail("smtp: \{what} failed with \{code}: \{lines[0]}")
  }
  (code, lines)
}

///|
/// AUTH PLAIN initial response: base64("\0user\0pass") (RFC 4954 §4).
/// Credentials are UTF-8 per RFC 4616 (F20): Char::to_int() is a UTF-16
/// code unit, so per-char to_byte would silently truncate non-ASCII
/// passwords.
fn plain_auth(user : String, pass : String) -> Bytes {
  let nul = Bytes::from_array([b'\x00'])
  nul.add(@utf8.encode(user)).add(nul).add(@utf8.encode(pass))
}

///|
/// Greeting only: consume the 220 banner (RFC 5321 §3.1).
async fn smtp_greeting(sock : &Sock) -> Unit {
  let (code, _) = read_reply(sock)
  guard code == 220 else { @error.fail("smtp: no greeting (\{code})") }
}

///|
/// STARTTLS negotiation over a plaintext connection (RFC 3207 §4):
/// EHLO, require the STARTTLS capability, send STARTTLS, consume the
/// 220 "ready to handshake" reply. The caller performs the TLS
/// handshake on the same connection; the session continues with the
/// second EHLO inside smtp_session (the plaintext EHLO's capabilities
/// are void after the upgrade).
//
// Only the native TLS transport calls this in production, so a non-test
// wasm/js build reports it as unused; the white-box SMTP suite drives it
// on every target, so keep it compiled everywhere and silence the false
// positive.
#warnings("-unused_value")
async fn smtp_starttls_ehlo(sock : &Sock, ehlo_domain : String) -> Unit {
  smtp_command(sock, "EHLO \{ehlo_domain}")
  let (_, caps) = expect(sock, 250, "EHLO")
  let has_starttls = caps.iter().any(line => line.has_prefix("STARTTLS"))
  guard has_starttls else {
    @error.fail("smtp: server does not advertise STARTTLS")
  }
  smtp_command(sock, "STARTTLS")
  ignore(expect(sock, 220, "STARTTLS"))
}

///|
/// Post-negotiation session: EHLO → [AUTH PLAIN] → MAIL FROM →
/// RCPT TO×N → DATA (dot-stuffed) → "." → QUIT. `from` and
/// `recipients` are envelope addr-specs (no display names). The QUIT
/// reply is not checked: a connection already torn down must not fail
/// an otherwise delivered message.
async fn smtp_session(
  sock : &Sock,
  message : String,
  from : String,
  recipients : Array[String],
  ehlo_domain : String,
  auth : (String, String)?,
) -> Unit {
  smtp_command(sock, "EHLO \{ehlo_domain}")
  let (_, caps) = expect(sock, 250, "EHLO")
  match auth {
    Some((user, pass)) => {
      let has_auth = caps
        .iter()
        .any(line => line.length() >= 4 && line[0:4].to_lower() == "auth")
      guard has_auth else {
        @error.fail(
          "smtp: credentials given but server does not advertise AUTH",
        )
      }
      smtp_command(sock, "AUTH PLAIN \{@base64.encode(plain_auth(user, pass))}")
      ignore(expect(sock, 235, "AUTH"))
    }
    None => ()
  }
  smtp_command(sock, "MAIL FROM:<\{from}>")
  ignore(expect(sock, 250, "MAIL FROM"))
  guard !recipients.is_empty() else {
    @error.fail("smtp: no envelope recipients")
  }
  for r in recipients {
    smtp_command(sock, "RCPT TO:<\{r}>")
    ignore(expect(sock, 250, "RCPT TO"))
  }
  smtp_command(sock, "DATA")
  ignore(expect(sock, 354, "DATA"))
  sock.write_all(@utf8.encode(dot_stuff(message)))
  smtp_command(sock, ".")
  ignore(expect(sock, 250, "end of DATA"))
  smtp_command(sock, "QUIT")
  let (_, _) = read_reply(sock)
}

///|
/// Run one full plaintext submission: greeting → session. Same wire
/// behavior as the pre-TLS single function; the TLS transports call
/// the pieces directly (plan tls-transport §3.3).
pub async fn smtp_send(
  sock : &Sock,
  message : String,
  from : String,
  recipients : Array[String],
  ehlo_domain : String,
  auth : (String, String)?,
) -> Unit {
  smtp_greeting(sock)
  smtp_session(sock, message, from, recipients, ehlo_domain, auth)
}
