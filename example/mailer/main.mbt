///|
/// example/mailer — compose a PGP signed+encrypted mail (body +
/// attachments) and hand it to a transport. See plan v2
/// (docs/plan-example-mailer.html) and HANDOFF §8.

///|
/// Callback recorder for --roundtrip (compose → self-decrypt).
struct RoundtripRecorder {
  bodies : Array[(String, String)]
  attachments : Array[(String, Bytes)]
  verified : Array[@api.VerifyStatus]
  errors : Array[String]
}

///|
fn new_recorder() -> RoundtripRecorder {
  RoundtripRecorder::{ bodies: [], attachments: [], verified: [], errors: [], }
}

///|
impl @mime.MimeCallbacks for RoundtripRecorder with fn on_body(
  self,
  body,
  mimetype,
) {
  self.bodies.push((body, mimetype))
}

///|
impl @mime.MimeCallbacks for RoundtripRecorder with fn on_attachment(
  self,
  headers,
  data,
) {
  let mut name = "?"
  for pair in headers {
    if pair.0.to_lower() == "content-disposition" &&
      pair.1.contains("filename=") {
      name = pair.1
    }
  }
  self.attachments.push((name, data))
}

///|
impl @mime.MimeCallbacks for RoundtripRecorder with fn on_verified(self, status) {
  self.verified.push(status)
}

///|
impl @mime.MimeCallbacks for RoundtripRecorder with fn on_error(self, message) {
  self.errors.push(message)
}

///|
struct Config {
  mut from : @mail.MailAddress?
  to : Array[@mail.MailAddress]
  mut subject : String
  mut body_file : String?
  attachments : Array[@mail.MailAttachment]
  mut sender_key : String?
  mut sender_key_pass_env : String?
  mut recipient_cert : String?
  mut domain : String?
  mut mode : String
  mut smtp_host : String
  mut smtp_port : Int
  mut smtp_user : String?
  mut smtp_pass_env : String?
  mut out : String
  mut roundtrip : Bool
}

///|
fn new_config() -> Config {
  Config::{
    from: None,
    to: [],
    subject: "",
    body_file: None,
    attachments: [],
    sender_key: None,
    sender_key_pass_env: None,
    recipient_cert: None,
    domain: None,
    mode: "file",
    smtp_host: "127.0.0.1",
    smtp_port: 2525,
    smtp_user: None,
    smtp_pass_env: None,
    out: "mail.eml",
    roundtrip: false,
  }
}

///|
fn usage() -> Unit {
  let lines = [
    "usage: moon run example/mailer -- [flags]", "  --from \"Name <a@b>\"              sender mailbox (required)",
    "  --to \"Name <b@c>\"                recipient, repeatable (required)", "  --subject TEXT                   ASCII subject (required)",
    "  --body-file PATH                 text body file (required)", "  --attach NAME:PATH               attachment, repeatable",
    "  --sender-key PATH                armored private key (required)", "  --sender-key-pass-env NAME       env var holding the key passphrase",
    "  --recipient-cert PATH            armored public key (required)", "  --domain DOM                     Message-ID / EHLO domain (required)",
    "  --mode smtp|file                 transport (default: file)", "  --smtp-host H --smtp-port N      default 127.0.0.1:2525",
    "  --smtp-user U --smtp-pass-env N  AUTH PLAIN creds (env var name)", "  --out PATH                       file-mode output (default mail.eml)",
    "  --roundtrip                      compose then self-decrypt (offline check)",
  ]
  for l in lines {
    println(l)
  }
}

///|
fn parse_address(s : String) -> @mail.MailAddress raise {
  let t = s.trim().to_owned()
  guard t != "" else {
    raise @error.PgpError::PgpError(msg="mailer: empty --from/--to value")
  }
  match t.split_once("<") {
    Some((name, rest)) => {
      guard rest.has_suffix(">") else {
        raise @error.PgpError::PgpError(msg="mailer: bad address '\{s}'")
      }
      let addr = rest[0:rest.length() - 1].trim().to_owned()
      @mail.MailAddress::{ display_name: name.trim().to_owned(), addr, }
    }
    None => @mail.MailAddress::{ display_name: "", addr: t, }
  }
}

///|
fn parse_args(argv : Array[String]) -> Config raise {
  let cfg = new_config()
  let mut i = 0
  while i < argv.length() {
    let flag = argv[i]
    let val = if flag == "--roundtrip" {
      ""
    } else {
      guard i + 1 < argv.length() else {
        raise @error.PgpError::PgpError(msg="mailer: \{flag} needs a value")
      }
      argv[i + 1]
    }
    match flag {
      "--from" => cfg.from = Some(parse_address(val))
      "--to" => cfg.to.push(parse_address(val))
      "--subject" => cfg.subject = val
      "--body-file" => cfg.body_file = Some(val)
      "--attach" => {
        let spec = val
        // split at the LAST colon so paths may contain colons
        let mut cut = -1
        for k, c in spec {
          if c == ':' {
            cut = k
          }
        }
        guard cut > 0 else {
          raise @error.PgpError::PgpError(
            msg="mailer: --attach expects NAME:PATH, got '\{spec}'",
          )
        }
        let name = spec[0:cut].to_owned()
        let path = spec[cut + 1:spec.length()].to_owned()
        cfg.attachments.push(@mail.MailAttachment::{
          filename: name,
          content_type: "application/octet-stream",
          data: @fs.read_file_to_bytes(path),
        })
      }
      "--sender-key" => cfg.sender_key = Some(val)
      "--sender-key-pass-env" => cfg.sender_key_pass_env = Some(val)
      "--recipient-cert" => cfg.recipient_cert = Some(val)
      "--domain" => cfg.domain = Some(val)
      "--mode" => {
        let m = val
        guard m == "smtp" || m == "file" else {
          raise @error.PgpError::PgpError(
            msg="mailer: --mode must be smtp|file",
          )
        }
        cfg.mode = m
      }
      "--smtp-host" => cfg.smtp_host = val
      "--smtp-port" => {
        let p = val
        let mut v = 0
        for c in p {
          let d = c.to_int() - 48
          guard d >= 0 && d <= 9 else {
            raise @error.PgpError::PgpError(
              msg="mailer: bad --smtp-port '\{p}'",
            )
          }
          v = v * 10 + d
        }
        cfg.smtp_port = v
      }
      "--smtp-user" => cfg.smtp_user = Some(val)
      "--smtp-pass-env" => cfg.smtp_pass_env = Some(val)
      "--out" => cfg.out = val
      "--roundtrip" => cfg.roundtrip = true
      _ => raise @error.PgpError::PgpError(msg="mailer: unknown flag '\{flag}'")
    }
    i = i + (if flag == "--roundtrip" { 1 } else { 2 })
  }
  cfg
}

///|
fn require_env(name : String) -> String raise {
  match @env.get_env_var(name) {
    Some(v) => v
    None =>
      raise @error.PgpError::PgpError(
        msg="mailer: environment variable \{name} is not set",
      )
  }
}

///|
fn load_recipient_public(path : String) -> @api.PublicKey raise {
  let text = @fs.read_file_to_string(path)
  @api.PublicKey::from_armored(text) catch {
    _ => @api.PrivateKey::from_armored(text).to_public()
  }
}

///|
fn run(cfg : Config) -> Unit raise {
  let from = match cfg.from {
    Some(f) => f
    None => raise @error.PgpError::PgpError(msg="mailer: --from is required")
  }
  guard cfg.subject != "" else {
    raise @error.PgpError::PgpError(msg="mailer: --subject is required")
  }
  guard !cfg.to.is_empty() else {
    raise @error.PgpError::PgpError(msg="mailer: --to is required")
  }
  let body_file = match cfg.body_file {
    Some(f) => f
    None =>
      raise @error.PgpError::PgpError(msg="mailer: --body-file is required")
  }
  let sender_key_path = match cfg.sender_key {
    Some(f) => f
    None =>
      raise @error.PgpError::PgpError(msg="mailer: --sender-key is required")
  }
  let cert_path = match cfg.recipient_cert {
    Some(f) => f
    None =>
      raise @error.PgpError::PgpError(
        msg="mailer: --recipient-cert is required",
      )
  }
  let domain = match cfg.domain {
    Some(d) => d
    None => raise @error.PgpError::PgpError(msg="mailer: --domain is required")
  }
  let body = @fs.read_file_to_string(body_file)
  let key = @api.PrivateKey::from_armored(
    @fs.read_file_to_string(sender_key_path),
  )
  let sender = match cfg.sender_key_pass_env {
    Some(env_name) => key.unlock(require_env(env_name))
    None => key
  }
  let recipient = load_recipient_public(cert_path)
  let message = @mail.build_encrypted_mail(
    from,
    cfg.to,
    subject=cfg.subject,
    text=body,
    attachments=cfg.attachments,
    signer=sender,
    recipients=[recipient],
    domain~,
  )
  if cfg.roundtrip {
    let cb = new_recorder()
    @mime.decrypt_mime(
      message,
      [sender],
      verifiers=[sender.to_public()],
      callbacks=cb,
    )
    if cb.errors.length() != 0 {
      for e in cb.errors {
        eprintln("roundtrip error: \{e}")
      }
      abort("roundtrip FAILED")
    }
    match cb.verified {
      [@api.Ok] => {
        println(
          "roundtrip: signature Ok, \{cb.bodies.length()} body, \{cb.attachments.length()} attachment(s)",
        )
        for b in cb.bodies {
          println("body[\{b.1}] = \{b.0}")
        }
        for a in cb.attachments {
          println("attachment: \{a.0} (\{a.1.length()} bytes)")
        }
        return
      }
      other => {
        println("roundtrip status: \{@netmail.status_names(other)}")
        abort("roundtrip FAILED")
      }
    }
  }
  let envelope_from = from.addr
  let envelope_rcpts : Array[String] = []
  for a in cfg.to {
    envelope_rcpts.push(a.addr)
  }
  match cfg.mode {
    "file" => {
      let t = @netmail.FileTransport::{ out_path: cfg.out, }
      t.send(message, envelope_from, envelope_rcpts)
    }
    "smtp" => {
      let t = @netmail.SmtpTransport::{
        host: cfg.smtp_host,
        port: cfg.smtp_port,
        ehlo_domain: domain,
        user: cfg.smtp_user,
        password: match cfg.smtp_pass_env {
          Some(name) => Some(require_env(name))
          None => None
        },
      }
      t.send(message, envelope_from, envelope_rcpts)
    }
    other => abort("mailer: unknown mode '\{other}'")
  }
  println("delivered via \{cfg.mode} transport")
}

///|
fn main {
  let args = @env.args()
  // Locate the first flag: moon run prefixes argv with its own tokens.
  let mut start = args.length()
  for i, a in args {
    if a.has_prefix("--") {
      start = i
      break
    }
  }
  let rest = args[start:args.length()].to_owned()
  if rest.is_empty() {
    usage()
    abort("mailer: no arguments")
  }
  let cfg = parse_args(rest) catch {
    e => {
      eprintln("\{e}")
      usage()
      abort("mailer: bad arguments")
    }
  }
  run(cfg) catch {
    e => {
      eprintln("\{e}")
      abort("mailer: failed")
    }
  }
}
