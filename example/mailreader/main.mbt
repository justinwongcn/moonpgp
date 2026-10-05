///|
/// example/mailreader — fetch mail over IMAP and decrypt+verify it
/// through @mime.decrypt_mime. Plan: docs/mail-fetch-plan.md (v1.1).
/// Plaintext policy mirrors the mailer: non-local hosts require the
/// explicit --allow-insecure opt-in; the recommended real-world path
/// is a local stunnel tunnel to the provider's IMAPS port.

///|
/// Callback recorder for decrypt_mime delivery (same shape as the
/// mailer's roundtrip recorder).
struct FetchRecorder {
  bodies : Array[(String, String)]
  attachments : Array[(String, Bytes)]
  verified : Array[@api.VerifyStatus]
  errors : Array[String]
}

///|
fn FetchRecorder::new() -> FetchRecorder {
  { bodies: [], attachments: [], verified: [], errors: [], }
}

///|
impl @mime.MimeCallbacks for FetchRecorder with fn on_body(self, body, mimetype) {
  self.bodies.push((body, mimetype))
}

///|
impl @mime.MimeCallbacks for FetchRecorder with fn on_attachment(
  self,
  headers,
  data,
) {
  let mut name = "attachment-\{self.attachments.length() + 1}"
  for pair in headers {
    if pair.0.to_lower() == "content-disposition" &&
      pair.1.contains("filename=") {
      let v = pair.1
      let cut = v.split("filename=").collect()
      if cut.length() == 2 {
        // stop at the next parameter separator, then strip quotes
        let seg = cut[1].split(";").collect()
        let candidate = seg[0].trim().trim(chars="\"").to_owned()
        // C1 (review): attachments are delivered regardless of the
        // signature outcome, and filenames come from the wire — a
        // "../" name would escape --out. Basename-only whitelist.
        let sanitized = sanitize_filename(candidate)
        if sanitized != "" {
          name = sanitized
        }
      }
    }
  }
  self.attachments.push((name, data))
}

///|
/// Wire-provided filename → safe local basename. Empty/`.`/`..`/path
/// separators/control characters are rejected (empty result = caller
/// keeps its numbered fallback).
fn sanitize_filename(name : String) -> String {
  let mut last = -1
  for i, c in name {
    if c == '/' || c == '\\' {
      last = i
    }
  }
  let base = name[last + 1:name.length()].to_owned()
  guard base != "" && base != "." && base != ".." else { return "" }
  for c in base {
    let v = c.to_int()
    guard v >= 0x20 && v <= 0x7E else { return "" }
  }
  base
}

///|
impl @mime.MimeCallbacks for FetchRecorder with fn on_verified(self, status) {
  self.verified.push(status)
}

///|
impl @mime.MimeCallbacks for FetchRecorder with fn on_error(self, message) {
  self.errors.push(message)
}

///|
struct Config {
  mut host : String
  mut port : Int
  mut user : String?
  mut pass_env : String?
  mut folder : String
  mut last_n : Int
  mut fetch_uid : Int?
  mut out_dir : String
  keys : Array[String]
  certs : Array[String]
  mut allow_insecure : Bool
}

///|
fn Config::new() -> Config {
  {
    host: "127.0.0.1",
    port: 1143,
    user: None,
    pass_env: None,
    folder: "INBOX",
    last_n: 5,
    fetch_uid: None,
    out_dir: ".",
    keys: [],
    certs: [],
    allow_insecure: false,
  }
}

///|
fn usage() -> Unit {
  let lines = [
    "usage: moon run example/mailreader -- [flags]", "  --imap-host H          default 127.0.0.1 (put stunnel in front for IMAPS)",
    "  --imap-port N          default 1143", "  --user ADDRESS         mailbox login (required)",
    "  --pass-env NAME        env var holding the auth code (required)", "  --folder NAME          default INBOX (the v1 subset)",
    "  --last N               list the newest N messages (default 5)", "  --fetch UID            fetch one message by UID, then decrypt+verify",
    "  --keys PATH            armored private key, repeatable (for --fetch)", "  --certs PATH           armored public key, repeatable (verifiers)",
    "  --out DIR              where .eml and attachments are written", "  --allow-insecure       opt-in for plaintext to a non-local host",
  ]
  for l in lines {
    println(l)
  }
}

///|
fn parse_args(argv : Array[String]) -> Config raise {
  let cfg = Config::new()
  let mut i = 0
  while i < argv.length() {
    let flag = argv[i]
    let val = if flag == "--allow-insecure" {
      ""
    } else {
      guard i + 1 < argv.length() else {
        @error.fail("mailreader: \{flag} needs a value")
      }
      argv[i + 1]
    }
    match flag {
      "--imap-host" => cfg.host = val
      "--imap-port" => cfg.port = parse_port(val)
      "--user" => cfg.user = Some(val)
      "--pass-env" => cfg.pass_env = Some(val)
      "--folder" => cfg.folder = val
      "--last" => cfg.last_n = parse_count(val)
      "--fetch" => {
        // an unparseable --fetch must fail loudly, not silently
        // degrade to list mode (review finding m5)
        let v = match @netmail.parse_int(val) {
          Some(v) => v
          None =>
            @error.fail(
              "mailreader: --fetch expects a numeric UID, got '\{val}'",
            )
        }
        guard v > 0 else {
          @error.fail(
            "mailreader: --fetch expects a positive UID, got '\{val}'",
          )
        }
        cfg.fetch_uid = Some(v)
      }
      "--out" => cfg.out_dir = val
      "--keys" => cfg.keys.push(val)
      "--certs" => cfg.certs.push(val)
      "--allow-insecure" => cfg.allow_insecure = true
      _ => @error.fail("mailreader: unknown flag '\{flag}'")
    }
    i = i + (if flag == "--allow-insecure" { 1 } else { 2 })
  }
  cfg
}

///|
fn parse_port(s : String) -> Int raise {
  let v = match @netmail.parse_int(s) {
    Some(v) => v
    None => @error.fail("mailreader: bad number '\{s}'")
  }
  guard v > 0 && v <= 65535 else { @error.fail("mailreader: bad port '\{s}'") }
  v
}

///|
/// Row limit for --last (not a port: separate bound, separate message).
fn parse_count(s : String) -> Int raise {
  let v = match @netmail.parse_int(s) {
    Some(v) => v
    None => @error.fail("mailreader: bad number '\{s}'")
  }
  guard v > 0 && v <= 1_000_000 else {
    @error.fail("mailreader: --last out of range (1..1000000)")
  }
  v
}

///|
fn require_env(name : String) -> String raise {
  match @env.get_env_var(name) {
    Some(v) => v
    None => @error.fail("mailreader: environment variable \{name} is not set")
  }
}

///|
/// Extract a header value from the fetched header-block bytes, joining
/// folded continuation lines. Byte-faithful read, lossy text decode
/// (values may be RFC 2047 words; that decode comes next).
fn header_value(headers : Bytes, name : String) -> String? {
  let text = @netmail.bytes_lossy(headers)
  let mut current_name = ""
  let mut current_value = ""
  let mut found : String? = None
  for raw_line in text.split("\r\n") {
    let line = raw_line.to_owned()
    if line == "" {
      continue
    }
    if (line.has_prefix(" ") || line.has_prefix("\t")) && current_name != "" {
      // RFC 5322 unfolding: the CRLF is removed, the folding whitespace
      // is kept as a single space
      current_value = current_value + " " + line.trim().to_owned()
      continue
    }
    // flush the previous header before starting a new one
    if current_name != "" {
      if current_name == name {
        found = Some(current_value)
      }
      current_value = ""
    }
    let colon = line.split(":").collect()
    if colon.length() >= 2 {
      current_name = colon[0].to_lower().to_owned()
      current_value = line[colon[0].length() + 1:line.length()]
        .trim()
        .to_owned()
    }
  }
  if current_name != "" && current_name == name {
    found = Some(current_value)
  }
  found
}

///|
fn load_private_keys(paths : Array[String]) -> Array[@api.PrivateKey] raise {
  let out : Array[@api.PrivateKey] = []
  for p in paths {
    out.push(@api.PrivateKey::from_armored(@fs.read_file_to_string(p)))
  }
  out
}

///|
fn load_verifiers(paths : Array[String]) -> Array[@api.PublicKey] raise {
  let out : Array[@api.PublicKey] = []
  for p in paths {
    let text = @fs.read_file_to_string(p)
    out.push(
      @api.PublicKey::from_armored(text) catch {
        _ => @api.PrivateKey::from_armored(text).to_public()
      },
    )
  }
  out
}

///|
fn join_path(dir : String, name : String) -> String {
  if dir.has_suffix("/") {
    "\{dir}\{name}"
  } else {
    "\{dir}/\{name}"
  }
}

///|
fn list_mailbox(cfg : Config, user : String, password : String) -> Unit raise {
  @netmail.with_imap_session(
    cfg.host,
    cfg.port,
    cfg.allow_insecure,
    user,
    password,
    cfg.folder,
    fn(client) -> Unit raise {
      let summaries = client.imap_fetch_recent(cfg.last_n)
      println(
        "folder \{cfg.folder}: \{client.state.exists} message(s), uidvalidity \{client.state.uidvalidity}, showing newest \{summaries.length()}",
      )
      for s in summaries {
        let from = match header_value(s.headers, "from") {
          Some(v) => @mail.decode_rfc2047(v)
          None => "?"
        }
        let subject = match header_value(s.headers, "subject") {
          Some(v) => @mail.decode_rfc2047(v)
          None => "?"
        }
        let date = match header_value(s.headers, "date") {
          Some(v) => v
          None => s.internaldate
        }
        println(
          "seq=\{s.seq} uid=\{s.uid} size=\{s.size} \{s.flags} | \{date} | \{from} | \{subject}",
        )
      }
    },
  )
}

///|
fn fetch_and_decrypt(
  cfg : Config,
  user : String,
  password : String,
  uid : Int,
) -> Unit raise {
  guard !cfg.keys.is_empty() else {
    @error.fail("mailreader: --fetch needs at least one --keys PATH")
  }
  let keys = load_private_keys(cfg.keys)
  let verifiers = load_verifiers(cfg.certs)
  @netmail.with_imap_session(
    cfg.host,
    cfg.port,
    cfg.allow_insecure,
    user,
    password,
    cfg.folder,
    fn(client) -> Unit raise {
      let raw = client.imap_fetch_message(uid)
      let eml_path = join_path(cfg.out_dir, "msg-\{uid}.eml")
      @fs.write_bytes_to_file(eml_path, raw)
      println("saved \{eml_path} (\{raw.length()} bytes)")
      // The library's decrypt pipeline is String-based; fetched PGP/MIME
      // is 7-bit (RFC 3156 §3), so the lossy decode is loss-free there.
      let cb = FetchRecorder::new()
      @mime.decrypt_mime(
        @netmail.bytes_lossy(raw),
        keys,
        verifiers~,
        callbacks=cb,
      )
      for e in cb.errors {
        eprintln("mime error: \{e}")
      }
      println("verify status: \{@netmail.status_names(cb.verified)}")
      for b in cb.bodies {
        println("--- body[\{b.1}] ---")
        println(b.0)
      }
      for a in cb.attachments {
        let path = join_path(cfg.out_dir, a.0)
        @fs.write_bytes_to_file(path, a.1)
        println("attachment: \{path} (\{a.1.length()} bytes)")
      }
      if cb.verified is [Ok] {
        println("decrypt+verify OK")
      } else if cb.errors.length() > 0 || cb.verified is [Failed] {
        abort("mailreader: decrypt/verify FAILED")
      }
    },
  )
}

///|
fn run(cfg : Config) -> Unit raise {
  let user = match cfg.user {
    Some(u) => u
    None => @error.fail("mailreader: --user is required")
  }
  let pass_env = match cfg.pass_env {
    Some(name) => name
    None => @error.fail("mailreader: --pass-env is required")
  }
  let password = require_env(pass_env)
  match cfg.fetch_uid {
    Some(uid) => fetch_and_decrypt(cfg, user, password, uid)
    None => list_mailbox(cfg, user, password)
  }
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
    abort("mailreader: no arguments")
  }
  let cfg = parse_args(rest) catch {
    e => {
      eprintln("\{e}")
      usage()
      abort("mailreader: bad arguments")
    }
  }
  run(cfg) catch {
    e => {
      eprintln("\{e}")
      abort("mailreader: failed")
    }
  }
}
