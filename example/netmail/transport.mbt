///|
/// Transport seam: how a composed .eml reaches the world. Two backends
/// per plan v2 — SMTP for local/relay submission (native, no TLS), and
/// file hand-off to a real MTA (msmtp) for the internet.
///
/// NOTE (toolchain, 2026-10-04): these are INHERENT methods, not a
/// trait — this moon build does not promote trait-impl methods across
/// packages (a value whose impl lives in this package cannot be
/// upcast/called from a consumer package), so a `MailTransport` trait
/// here would be unusable from external projects. The `Socket` seam
/// keeps its `pub(open)` trait: consumers implementing it upcast from
/// their OWN package, which works (same as @mime.MimeCallbacks).

///|
/// Writes the .eml to disk and prints the msmtp hand-off command. This
/// is the real-internet path: TLS, retries and queues are the MTA's
/// job, not ours.
pub(all) struct FileTransport {
  out_path : String
}

///|
pub fn FileTransport::send(
  self : FileTransport,
  message : String,
  from : String,
  recipients : Array[String],
) -> Unit raise {
  ignore(from)
  ignore(recipients)
  @fs.write_string_to_file(self.out_path, message)
  println("wrote \{self.out_path} (\{message.length()} chars)")
  println("send it with:  msmtp --read-envelope-from < \{self.out_path}")
}

///|
/// Minimal SMTP submission. No TLS by design (plan v2 §5/§8): AUTH is
/// refused on non-local plaintext connections so credentials can never
/// cross the open internet in the clear.
pub(all) struct SmtpTransport {
  host : String
  port : Int
  ehlo_domain : String
  user : String?
  password : String?
}

///|
pub fn SmtpTransport::send(
  self : SmtpTransport,
  message : String,
  from : String,
  recipients : Array[String],
) -> Unit raise {
  let auth : (String, String)? = match (self.user, self.password) {
    (Some(u), Some(p)) => Some((u, p))
    (Some(_), None) =>
      raise @error.PgpError::PgpError(
        msg="smtp: --smtp-user given but --smtp-pass-env not set",
      )
    (None, Some(_)) =>
      raise @error.PgpError::PgpError(
        msg="smtp: --smtp-pass-env given but --smtp-user not set",
      )
    (None, None) => None
  }
  if auth is Some(_) && !is_local_host(self.host) {
    raise @error.PgpError::PgpError(
      msg="smtp: refusing AUTH over plaintext to non-local host '\{self.host}' (no TLS; use --mode file + msmtp)",
    )
  }
  let sock = connect_socket(self.host, self.port)
  send_over(sock, message, from, recipients, self.ehlo_domain, auth)
}

///|
/// Submit over an established socket, closing it on every outcome —
/// the close-on-error guarantee lives here and is asserted in the
/// white-box tests.
fn send_over(
  sock : &Socket,
  message : String,
  from : String,
  recipients : Array[String],
  ehlo_domain : String,
  auth : (String, String)?,
) -> Unit raise {
  errdefer sock.close()
  smtp_send(sock, message, from, recipients, ehlo_domain, auth)
  sock.close()
}
