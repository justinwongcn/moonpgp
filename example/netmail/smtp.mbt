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
  guard line.length() >= 3 else {
    raise @error.PgpError::PgpError(msg="smtp: short reply '\{line}'")
  }
  let mut code = 0
  for k in 0..<3 {
    let v = line[k].to_int() - 48
    guard v >= 0 && v <= 9 else {
      raise @error.PgpError::PgpError(msg="smtp: malformed reply '\{line}'")
    }
    code = code * 10 + v
  }
  code
}

///|
fn read_reply(sock : &Socket) -> (Int, Array[String]) raise {
  let first = sock.read_line()
  let code = reply_code(first)
  let lines : Array[String] = []
  let mut line = first
  while line.length() >= 4 && line[3] == '-' {
    lines.push(line[4:].to_owned())
    line = sock.read_line()
    let cont = reply_code(line)
    guard cont == code else {
      raise @error.PgpError::PgpError(
        msg="smtp: inconsistent multi-line reply (\{code} vs \{cont})",
      )
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
fn smtp_command(sock : &Socket, line : String) -> Unit raise {
  sock.write_all(@utf8.encode(line + "\r\n"))
}

///|
fn expect(
  sock : &Socket,
  want : Int,
  what : String,
) -> (Int, Array[String]) raise {
  let (code, lines) = read_reply(sock)
  guard code == want else {
    raise @error.PgpError::PgpError(
      msg="smtp: \{what} failed with \{code}: \{lines[0]}",
    )
  }
  (code, lines)
}

///|
/// AUTH PLAIN initial response: base64("\0user\0pass") (RFC 4954 §4).
fn plain_auth(user : String, pass : String) -> Bytes {
  let raw : Array[Byte] = [b'\x00']
  for c in user {
    raw.push(c.to_int().to_byte())
  }
  raw.push(b'\x00')
  for c in pass {
    raw.push(c.to_int().to_byte())
  }
  Bytes::from_array(raw)
}

///|
/// Run one full submission: greeting → EHLO → [AUTH PLAIN] →
/// MAIL FROM → RCPT TO×N → DATA (dot-stuffed) → "." → QUIT. `from` and
/// `recipients` are envelope addr-specs (no display names). The QUIT
/// reply is not checked: a connection already torn down must not fail
/// an otherwise delivered message.
pub fn smtp_send(
  sock : &Socket,
  message : String,
  from : String,
  recipients : Array[String],
  ehlo_domain : String,
  auth : (String, String)?,
) -> Unit raise {
  let (code, _) = read_reply(sock)
  guard code == 220 else {
    raise @error.PgpError::PgpError(msg="smtp: no greeting (\{code})")
  }
  smtp_command(sock, "EHLO \{ehlo_domain}")
  let (_, caps) = expect(sock, 250, "EHLO")
  match auth {
    Some((user, pass)) => {
      let mut has_auth = false
      for line in caps {
        if line.length() >= 4 && line[0:4].to_lower() == "auth" {
          has_auth = true
        }
      }
      guard has_auth else {
        raise @error.PgpError::PgpError(
          msg="smtp: credentials given but server does not advertise AUTH",
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
    raise @error.PgpError::PgpError(msg="smtp: no envelope recipients")
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
