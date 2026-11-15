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
  // Scan separators in UTF-16 code-unit space (audit F22): `for i, c in`
  // counts CHARACTERS while `name[i:j]` slices by CODE UNIT — the two
  // index spaces diverged on any supplementary-plane character, letting
  // a separator survive into the base by index drift. `s[i]` is the
  // code-unit Int, matching the slice below.
  let mut last = -1
  for i in 0..<name.length() {
    if name[i] == 0x2F || name[i] == 0x5C {
      last = i
    }
  }
  let base = name[last + 1:name.length()].to_owned()
  guard base != "" && base != "." && base != ".." else { return "" }
  // The drifted index used to be able to START the base on a separator
  // ("/.."); refuse that shape outright instead of trusting join_path.
  guard base[0] != 0x2F && base[0] != 0x5C else { return "" }
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
  mut port : Int32
  mut user : String?
  mut pass_env : String?
  mut folder : String
  mut last_n : Int32
  mut fetch_uid : Int32?
  mut resync : Bool
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
    resync: false,
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
    "  --resync               with --fetch: accept a UIDVALIDITY change and re-list",
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
    // Boolean flags consume no value (audit M1): --resync used to fall
    // through the value-taking path, swallowing the NEXT argument as its
    // unused value and skipping it — the documented "--resync --fetch 42"
    // then failed on "unknown flag '42'" and "--resync --out DIR" lost
    // --out silently.
    let val = if flag == "--allow-insecure" || flag == "--resync" {
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
      "--resync" => cfg.resync = true
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
    i = i +
      (if flag == "--allow-insecure" || flag == "--resync" { 1 } else { 2 })
  }
  cfg
}

///|
fn parse_port(s : String) -> Int32 raise {
  let v = match @netmail.parse_int(s) {
    Some(v) => v
    None => @error.fail("mailreader: bad number '\{s}'")
  }
  guard v > 0 && v <= 65535 else { @error.fail("mailreader: bad port '\{s}'") }
  v
}

///|
/// Row limit for --last (not a port: separate bound, separate message).
fn parse_count(s : String) -> Int32 raise {
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
  // StringBuilder (audit F23): the per-continuation `a + " " + b` made
  // the folding join O(total^2) — server-controlled HEADER.FIELDS
  // literal became quadratic CPU.
  let mut value = StringBuilder()
  let mut found : String? = None
  for raw_line in text.split("\r\n") {
    let line = raw_line.to_owned()
    if line == "" {
      continue
    }
    if (line.has_prefix(" ") || line.has_prefix("\t")) && current_name != "" {
      // RFC 5322 unfolding: the CRLF is removed, the folding whitespace
      // is kept as a single space
      value.write_string(" ")
      value.write_string(line.trim().to_owned())
      continue
    }
    let colon = line.split(":").collect()
    // A line that does not parse as a header — no colon, or a nameless
    // ":junk" — is skipped wholesale (F23 regression, JEV j8). It is not
    // a header start, so it must neither write into `value` (that glued
    // attacker text onto the next real header's value: "junk"+"real" ->
    // "junkreal") nor flush the previous header (that reset `value` and
    // made the last real header read back as empty).
    if colon.length() < 2 || colon[0] == "" {
      continue
    }
    // flush the previous header before starting a new one
    if current_name != "" {
      if current_name == name {
        found = Some(value.to_string())
      }
      value = StringBuilder()
    }
    current_name = colon[0].to_lower().to_owned()
    value.write_string(
      line[colon[0].length() + 1:line.length()].trim().to_owned(),
    )
  }
  if current_name != "" && current_name == name {
    found = Some(value.to_string())
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
/// UIDVALIDITY persistence (audit F26): list and fetch are separate
/// sessions and a mailbox rebuilt between them silently re-points UIDs.
/// The state file records host|user|folder→uidvalidity: `--last`
/// refreshes the record (the user saw that list), `--fetch` refuses on a
/// mismatch — delete the state file to accept a deliberate reset.
fn uidvalidity_state_path(cfg : Config) -> String {
  join_path(cfg.out_dir, ".mailreader-uidvalidity.txt")
}

///|
/// Percent-encode one state-file key component (JEV j14): `|` is the
/// record separator, so a folder like "Work|2024" collided across
/// entries and made `check_uidvalidity` hard-reject a legitimate
/// generation. `%` escapes itself to keep the encoding unambiguous.
fn state_key_component(s : String) -> String {
  let out = StringBuilder()
  for c in s {
    match c {
      '%' => out.write_string("%25")
      '|' => out.write_string("%7C")
      '\r' => out.write_string("%0D")
      '\n' => out.write_string("%0A")
      _ => out.write_char(c)
    }
  }
  out.to_string()
}

///|
fn uidvalidity_state_key(
  cfg : Config,
  user : String,
  folder : String,
) -> String {
  "\{state_key_component(cfg.host)}|\{state_key_component(user)}|\{state_key_component(folder)}"
}

///|
fn record_uidvalidity(
  cfg : Config,
  user : String,
  folder : String,
  uidvalidity : Int64,
) -> Unit raise {
  let key = uidvalidity_state_key(cfg, user, folder)
  let path = uidvalidity_state_path(cfg)
  let existing = @fs.read_file_to_string(path) catch { _ => "" }
  let kept : Array[String] = []
  for line in existing.split("\n") {
    let l = line.to_owned()
    if l != "" && !l.has_prefix("\{key}|") {
      kept.push(l)
    }
  }
  kept.push("\{key}|\{uidvalidity}")
  @fs.write_string_to_file(path, kept.join("\n") + "\n")
}

///|
fn check_uidvalidity(
  cfg : Config,
  user : String,
  folder : String,
  uidvalidity : Int64,
) -> Unit raise {
  let key = uidvalidity_state_key(cfg, user, folder)
  let existing = @fs.read_file_to_string(uidvalidity_state_path(cfg)) catch {
    _ => ""
  }
  for line in existing.split("\n") {
    if line.has_prefix("\{key}|") {
      let stored = line[key.length() + 1:line.length()]
      let got = uidvalidity.to_string()
      guard stored == got else {
        @error.fail(
          "mailreader: UIDVALIDITY for \{folder} changed (\{stored} -> \{got}); UIDs may point at different mail — delete \{uidvalidity_state_path(cfg)} if the reset is intentional",
        )
      }
      return
    }
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
    fn(client) -> Unit raise { print_recent(client, cfg, user) },
  )
}

///|
/// The --last listing, shared with the --resync recovery path: fresh
/// baseline record plus the newest messages (F26 + leftover #3).
fn print_recent(
  client : @netmail.ImapClient,
  cfg : Config,
  user : String,
) -> Unit raise {
  let summaries = client.imap_fetch_recent(cfg.last_n)
  println(
    "folder \{cfg.folder}: \{client.state.exists} message(s), uidvalidity \{client.state.uidvalidity}, showing newest \{summaries.length()}",
  )
  // A fresh list refreshes the baseline: the user just saw this
  // mailbox generation (audit F26).
  record_uidvalidity(cfg, user, cfg.folder, client.state.uidvalidity)
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
      // Server-controlled text hits the terminal directly here (the
      // decoded from/subject go through decode_rfc2047's filter); a
      // hostile server escapes through the sibling field otherwise
      // (hacker-round composition finding E2).
      Some(v) => @mail.sanitize_terminal(v)
      None => @mail.sanitize_terminal(s.internaldate)
    }
    let flags = @mail.sanitize_terminal(s.flags)
    println(
      "seq=\{s.seq} uid=\{s.uid} size=\{s.size} \{flags} | \{date} | \{from} | \{subject}",
    )
  }
}

///|
/// Would `check_uidvalidity` reject this generation? Separate predicate
/// so the --resync path can branch before the hard rejection (leftover
/// #3). Absent baseline means no mismatch (the record is created by
/// --last / --resync).
fn uidvalidity_mismatch(
  cfg : Config,
  user : String,
  folder : String,
  got : Int64,
) -> Bool {
  let existing = @fs.read_file_to_string(uidvalidity_state_path(cfg)) catch {
    _ => ""
  }
  let key = uidvalidity_state_key(cfg, user, folder)
  for line in existing.split("\n") {
    if line.has_prefix("\{key}|") {
      let stored = line[key.length() + 1:line.length()]
      return stored != got.to_string()
    }
  }
  false
}

///|
fn fetch_and_decrypt(
  cfg : Config,
  user : String,
  password : String,
  uid : Int32,
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
      // The mailbox generation must match what the user last listed
      // (audit F26); a mismatch means UIDs may point at different mail.
      // --resync (mbsync-style, leftover #3 user decision): adopt the
      // server's current generation and re-list — UIDs are meaningless
      // across generations, so recovery is re-reconcile by listing and
      // picking a fresh UID, exactly what mbsync does on its own.
      if cfg.resync &&
        uidvalidity_mismatch(cfg, user, cfg.folder, client.state.uidvalidity) {
        println(
          "mailreader: UIDVALIDITY changed; resyncing — old UIDs are invalid, showing newest messages",
        )
        print_recent(client, cfg, user)
        return
      }
      check_uidvalidity(cfg, user, cfg.folder, client.state.uidvalidity)
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
      match delivery_failure(cb.errors.length(), cb.verified) {
        None => println("decrypt+verify OK")
        Some(why) =>
          // D2: a signature from a revoked or expired key is not a
          // success either — only [Ok] (or the empty/no-verifier case)
          // counts as a clean delivery, and anything else must not be
          // archived silently with exit code 0. The gate below is the
          // comment made true (cleanup round E6): NotSigned/NoVerifier
          // used to fall between the branches and exit 0.
          abort("mailreader: decrypt/verify FAILED (\{why})")
      }
    },
  )
}

///|
/// D2 delivery gate (cleanup round E6): non-zero exit and no archiving
/// unless the delivery is clean — verification [Ok] (or nothing
/// attempted, when no verifiers were requested) and no reported errors.
fn delivery_failure(
  error_count : Int32,
  verified : Array[@api.VerifyStatus],
) -> String? {
  if error_count > 0 {
    return Some("\{error_count} error(s) reported")
  }
  for s in verified {
    if !(s is @api.Ok) {
      return Some(@netmail.status_names([s]))
    }
  }
  None
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
