///|
/// Transport seam: how a composed .eml reaches the world. Three backends
/// — SMTP for local/relay submission (this file: plaintext only, the
/// --smtp-tls none path), encrypted submission in transport_tls.mbt
/// (implicit 465 / STARTTLS 587), and file hand-off to a real MTA
/// (msmtp) for the internet.
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
/// Minimal plaintext SMTP submission (the --smtp-tls none path). AUTH
/// is refused on non-local connections so credentials can never cross
/// the open internet in the clear; encrypted submission lives in
/// TlsTransport, where TLS makes AUTH PLAIN legitimate.
pub(all) struct SmtpTransport {
  host : String
  port : Int
  ehlo_domain : String
  user : String?
  password : String?
}

///|
pub async fn SmtpTransport::send(
  self : SmtpTransport,
  message : String,
  from : String,
  recipients : Array[String],
) -> Unit {
  let auth : (String, String)? = match (self.user, self.password) {
    (Some(u), Some(p)) => Some((u, p))
    (Some(_), None) =>
      @error.fail("smtp: --smtp-user given but --smtp-pass-env not set")
    (None, Some(_)) =>
      @error.fail("smtp: --smtp-pass-env given but --smtp-user not set")
    (None, None) => None
  }
  if auth is Some(_) && !is_local_host(self.host) {
    @error.fail(
      "smtp: refusing AUTH over plaintext to non-local host '\{self.host}' (credentials would cross the open internet; use --smtp-tls implicit|starttls, or --mode file + msmtp)",
    )
  }
  let sock = connect_sock(self.host, self.port)
  send_over(sock, message, from, recipients, self.ehlo_domain, auth)
}

///|
/// Submit over an established socket, closing it on every outcome —
/// the close-on-error guarantee lives here and is asserted in the
/// white-box tests.
async fn send_over(
  sock : &Sock,
  message : String,
  from : String,
  recipients : Array[String],
  ehlo_domain : String,
  auth : (String, String)?,
) -> Unit {
  errdefer Sock::close(sock)
  smtp_send(sock, message, from, recipients, ehlo_domain, auth)
  Sock::close(sock)
}
