///|
/// moonpgp — OpenPGP mail encryption demo CLI.
///
/// Passphrases travel via `--pass-env NAME` (the named environment
/// variable), never on the command line: argv lands in shell history and
/// `ps` output (D1, matching the mailer/mailreader examples).
///
///   moon run cmd/main -- help
///   moon run cmd/main -- keygen "Name <me@example.com>" key.asc pub.asc [bits]
///   moon run cmd/main -- encpass --pass-env NAME <in> <out>
///   moon run cmd/main -- decpass --pass-env NAME <in> <out>
///   moon run cmd/main -- encpub <public-key.asc> <in> <out>
///   moon run cmd/main -- decpriv <secret-key.asc> [--pass-env NAME] <in> <out>
///   moon run cmd/main -- sign <secret-key.asc> <in> <out.sig>
///   moon run cmd/main -- verify <public-key.asc> <in> <sig.asc>
///   moon run cmd/main -- lock <secret-key.asc> --pass-env NAME
///   moon run cmd/main -- unlock <secret-key.asc> --pass-env NAME
fn main {
  let args = @env.args()
  if args.length() < 2 {
    usage()
  }
  // `help`, `--help` and `-h` print the usage text and exit successfully.
  if args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
    print_usage()
    return
  }
  let rest : Array[String] = args[2:args.length()].to_owned()
  run(args[1], rest) catch {
    e => {
      println("error: \{e}")
      abort("command failed")
    }
  }
}

///|
fn run(command : String, rest : Array[String]) -> Unit raise {
  match command {
    "keygen" => {
      check_args(rest.length(), 3)
      let key = @api.generate_key(rest[0], bits=parse_bits(rest))
      // Key generation writes the fresh unlocked key by definition (F17):
      // the export gate stays, and the intent is explicit here.
      @fs.write_string_to_file(rest[1], key.to_armored(allow_unlocked=true))
      @fs.write_string_to_file(rest[2], key.to_public().to_armored())
      println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    }
    "edkeygen" => {
      check_args(rest.length(), 3)
      let key = @api.generate_ed25519_key(rest[0])
      // Key generation writes the fresh unlocked key by definition (F17).
      @fs.write_string_to_file(rest[1], key.to_armored(allow_unlocked=true))
      @fs.write_string_to_file(rest[2], key.to_public().to_armored())
      println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    }
    "v6keygen" => {
      check_args(rest.length(), 3)
      let key = @api.generate_ed25519_v6_key(rest[0])
      // Key generation writes the fresh unlocked key by definition (F17).
      @fs.write_string_to_file(rest[1], key.to_armored(allow_unlocked=true))
      @fs.write_string_to_file(rest[2], key.to_public().to_armored())
      println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    }
    "encpass" => {
      let (pass, pos) = pass_from_args(rest)
      check_args(pos.length(), 2)
      let data = @fs.read_file_to_bytes(pos[0])
      // Stamp the literal packet with the input's file name so the
      // backup-file scenario keeps a trace of what was encrypted.
      let file_name = basename(pos[0])
      // Optional trailing "aead" selects the v5 SKESK + tag-20 shape
      // (GnuPG --force-aead interop) instead of v4 SKESK + SEIPD v1.
      let aead = pos.length() >= 3 && pos[2] == "aead"
      let armored = @api.encrypt_with_password(data, pass, aead~, file_name~)
      @fs.write_string_to_file(pos[1], armored)
      println("wrote \{pos[1]}")
    }
    "decpass" => {
      let (pass, pos) = pass_from_args(rest)
      check_args(pos.length(), 2)
      let armored = @fs.read_file_to_string(pos[0])
      let plain = @api.decrypt_with_password(armored, pass)
      @fs.write_bytes_to_file(pos[1], plain)
      println("wrote \{pos[1]}")
    }
    "encpub" => {
      check_args(rest.length(), 3)
      let key = @api.PublicKey::from_armored(@fs.read_file_to_string(rest[0]))
      let data = @fs.read_file_to_bytes(rest[1])
      let armored = @api.encrypt_to_recipients(data, [key])
      @fs.write_string_to_file(rest[2], armored)
      println("wrote \{rest[2]}")
    }
    "decpriv" => {
      let (pass, pos) = pass_env_from_args(rest)
      check_args(pos.length(), 3)
      let key_text = @fs.read_file_to_string(pos[0])
      let key = @api.PrivateKey::from_armored(key_text)
      // Snapshot the lock state BEFORE unlocking: unlock clears s2k_usage,
      // so key.is_locked() is false afterwards. A locked key requires
      // --pass-env; an unlocked key needs none (the flag stays optional
      // here, unlike the password-only commands).
      let key = if key.is_locked() {
        match pass {
          Some(p) => key.unlock(p)
          None =>
            @error.fail(
              "cli: \{pos[0]} is locked; pass the passphrase via --pass-env NAME",
            )
        }
      } else {
        key
      }
      let data = @api.decrypt_with_private_key(
        @fs.read_file_to_string(pos[1]),
        key,
      )
      @fs.write_bytes_to_file(pos[2], data)
      println("wrote \{pos[2]}")
    }
    "sign" => {
      check_args(rest.length(), 3)
      let key = @api.PrivateKey::from_armored(@fs.read_file_to_string(rest[0]))
      let data = @fs.read_file_to_bytes(rest[1])
      let sig = @api.sign_detached(data.exact_view(), key)
      @fs.write_string_to_file(rest[2], sig)
      println("wrote \{rest[2]}")
    }
    "verify" => {
      check_args(rest.length(), 3)
      let key = @api.PublicKey::from_armored(@fs.read_file_to_string(rest[0]))
      let data = @fs.read_file_to_bytes(rest[1])
      let sig = @fs.read_file_to_string(rest[2])
      match @api.verify_detached(data.exact_view(), sig, key) {
        @api.Ok => println("Good signature")
        @api.NotSigned => {
          println("No signature found")
          abort("verification failed")
        }
        @api.NoVerifier => {
          println("No verifier for this signature")
          abort("verification failed")
        }
        @api.Failed => {
          println("Bad signature")
          abort("verification failed")
        }
        @api.KeyRevoked => {
          println("Signing key is revoked")
          abort("verification failed")
        }
        @api.Expired => {
          println("Signing key or signature is expired")
          abort("verification failed")
        }
      }
    }
    "lock" => {
      let (pass, pos) = pass_from_args(rest)
      check_args(pos.length(), 1)
      let key = @api.PrivateKey::from_armored(@fs.read_file_to_string(pos[0]))
      let locked = key.lock(pass)
      replace_file_atomic(pos[0], locked.to_armored())
      println(
        "locked \{pos[0]} (decryption and signing now require the passphrase)",
      )
    }
    "unlock" => {
      let (pass, pos) = pass_from_args(rest)
      check_args(pos.length(), 1)
      let key = @api.PrivateKey::from_armored(@fs.read_file_to_string(pos[0]))
      let open = key.unlock(pass)
      // `unlock` exists to store the key without passphrase protection
      // (F17): the explicit opt-in is the command's own intent.
      replace_file_atomic(pos[0], open.to_armored(allow_unlocked=true))
      println(
        "unlocked \{pos[0]} (the secret key is now stored without passphrase protection)",
      )
    }
    _ => usage()
  }
}

///|
/// Strip `--pass-env NAME` from the arguments, returning the passphrase
/// read from that environment variable together with the remaining
/// positional arguments. The value never appears in argv: command lines
/// land in shell history and `ps` output (D1; same convention as the
/// mailer/mailreader examples).
fn pass_from_args(rest : Array[String]) -> (String, Array[String]) raise {
  let (pass, pos) = pass_env_from_args(rest)
  match pass {
    Some(p) => (p, pos)
    None =>
      @error.fail(
        "cli: pass the passphrase via --pass-env NAME (an environment variable), not on the command line",
      )
  }
}

///|
/// Like `pass_from_args` but the flag is optional (for commands where a
/// passphrase is only needed in some states, e.g. `decpriv` on an
/// unlocked key).
fn pass_env_from_args(rest : Array[String]) -> (String?, Array[String]) raise {
  let out : Array[String] = []
  let mut name : String? = None
  let mut i = 0
  while i < rest.length() {
    if rest[i] == "--pass-env" {
      if i + 1 >= rest.length() {
        @error.fail("cli: --pass-env needs the NAME of an environment variable")
      }
      name = Some(rest[i + 1])
      i += 1
    } else {
      out.push(rest[i])
    }
    i += 1
  }
  match name {
    Some(n) =>
      match @env.get_env_var(n) {
        Some(v) => (Some(v), out)
        None =>
          @error.fail("cli: environment variable \{n} (--pass-env) is not set")
      }
    None => (None, out)
  }
}

///|
fn check_args(got : Int32, want : Int32) -> Unit {
  if got < want {
    usage()
  }
}

///|
/// The final path component, stamped into encrypted literal packets.
/// Scan in UTF-16 code-unit space (audit M2, the cmd twin of F22): the
/// character-count loop vs the code-unit slice drift let a separator
/// survive into the basename whenever a supplementary-plane character
/// preceded the last '/'.
fn basename(path : String) -> String {
  let mut last = -1
  for i in 0..<path.length() {
    if path[i] == 0x2F {
      last = i
    }
  }
  if last < 0 {
    path
  } else {
    path[last + 1:path.length()].to_owned()
  }
}

///|
/// Explicit bit count for keygen (the RFC 9580 floor applies when the
/// argument is absent). Garbage fails loudly (review finding m5: an
/// unparseable parameter never degrades quietly to the default).
fn parse_bits(rest : Array[String]) -> Int32 raise {
  match rest[3:rest.length()].to_owned() {
    [b, ..] =>
      @string.parse_int(b) catch {
        _ =>
          @error.fail(
            "cli: unparseable key bit count '\{b}' (floor 3072, e.g. 3072 or 4096)",
          )
      }
    _ => 3072
  }
}

///|
/// NUL-terminated UTF-8 copy of a path for the C bridge.
fn cstring(s : String) -> Bytes raise {
  let out : Array[Byte] = []
  for b in @primitives.utf8_bytes(s) {
    out.push(b)
  }
  out.push(b'\x00')
  Bytes::from_array(out)
}

///|
/// POSIX rename(2) — atomic within one filesystem.
#cfg(target="native")
#borrow(src, dst)
extern "c" fn c_rename(src : Bytes, dst : Bytes) -> Int32 = "rename"

///|
/// In-place replace via temp file + rename(2) (audit CMD-1): the old
/// truncate-then-write destroyed the only copy of a secret key when the
/// write failed midway (ENOSPC, crash, kill). Native targets — where the
/// CLI ships — write the new content to a sibling temp file and rename it
/// over the target, so the original survives every mid-write failure.
/// The temp file is chmod 0600 before the swap (audit f3): a fresh file
/// inherits the umask default (0644) and the rename would swap the inode
/// out from under a hand-tightened private-key mode. Write and chmod
/// failures clean the temp file up. Non-native targets keep the plain
/// write.
#cfg(target="native")
#borrow(path)
extern "c" fn c_chmod(path : Bytes, mode : Int32) -> Int32 = "chmod"

///|
#cfg(target="native")
fn replace_file_atomic(path : String, content : String) -> Unit raise {
  let tmp = "\{path}.moonpgp-tmp"
  // Any failure after the temp write (mid-write ENOSPC, chmod, rename)
  // leaves no half-written residue behind.
  errdefer {
    let _ = @fs.remove_file(tmp) catch { _ => () }
  }
  // Close the mode window (audit pv6): create the temp file EMPTY, chmod
  // it 0600, and only then write the key material — writing first left
  // the private-key bytes world-readable between the create and the
  // chmod (a fresh file inherits the umask default, and the temp name is
  // predictable). Truncating our own 0600 file keeps the mode.
  @fs.write_string_to_file(tmp, "")
  guard c_chmod(cstring(tmp), 0o600) == 0 else {
    @error.fail("cli: could not set 0600 on \{tmp}")
  }
  @fs.write_string_to_file(tmp, content)
  guard c_rename(cstring(tmp), cstring(path)) == 0 else {
    // The errdefer above removes the temp file on this exit path.
    @error.fail(
      "cli: could not replace \{path} (rename failed); rerun the command",
    )
  }
}

///|
#cfg(not(target="native"))
fn replace_file_atomic(path : String, content : String) -> Unit raise {
  @fs.write_string_to_file(path, content)
}

///|
fn usage() -> Unit {
  print_usage()
  abort("missing arguments")
}

///|
fn print_usage() -> Unit {
  println(
    "usage:\n" +
    "  help                                     print this message\n" +
    "  keygen \"Name <me@example.com>\" key.asc pub.asc [bits]\n" +
    "  edkeygen \"Name <me@example.com>\" key.asc pub.asc\n" +
    "  v6keygen \"Name <me@example.com>\" key.asc pub.asc   (RFC 9580 v6 Ed25519)\n" +
    "  encpass --pass-env NAME <in> <out> [aead]  (aead = tag-20/GnuPG shape)\n" +
    "  decpass --pass-env NAME <in> <out>\n" +
    "  encpub <public-key.asc> <in> <out>\n" +
    "  decpriv <secret-key.asc> [--pass-env NAME] <in> <out>\n" +
    "  sign <secret-key.asc> <in> <out.sig>\n" +
    "  verify <public-key.asc> <in> <sig.asc>\n" +
    "  lock <secret-key.asc> --pass-env NAME     (protect the stored secret key)\n" +
    "  unlock <secret-key.asc> --pass-env NAME   (strip passphrase protection)",
  )
}
