///|
/// moonpgp — OpenPGP mail encryption demo CLI.
///
///   moon run cmd/main -- help
///   moon run cmd/main -- keygen "Name <me@example.com>" key.asc pub.asc [bits]
///   moon run cmd/main -- encpass <passphrase> <in> <out>
///   moon run cmd/main -- decpass <passphrase> <in> <out>
///   moon run cmd/main -- encpub <public-key.asc> <in> <out>
///   moon run cmd/main -- decpriv <secret-key.asc> [passphrase] <in> <out>
///   moon run cmd/main -- sign <secret-key.asc> <in> <out.sig>
///   moon run cmd/main -- verify <public-key.asc> <in> <sig.asc>
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
      let key = @api.generate_key(rest[0], bits=parse_bits(rest, 2048))
      @fs.write_string_to_file(rest[1], key.to_armored())
      @fs.write_string_to_file(rest[2], key.to_public().to_armored())
      println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    }
    "edkeygen" => {
      check_args(rest.length(), 3)
      let key = @api.generate_ed25519_key(rest[0])
      @fs.write_string_to_file(rest[1], key.to_armored())
      @fs.write_string_to_file(rest[2], key.to_public().to_armored())
      println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    }
    "v6keygen" => {
      check_args(rest.length(), 3)
      let key = @api.generate_ed25519_v6_key(rest[0])
      @fs.write_string_to_file(rest[1], key.to_armored())
      @fs.write_string_to_file(rest[2], key.to_public().to_armored())
      println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    }
    "encpass" => {
      check_args(rest.length(), 3)
      let data = @fs.read_file_to_bytes(rest[1])
      // Optional trailing "aead" selects the v5 SKESK + tag-20 shape
      // (GnuPG --force-aead interop) instead of v4 SKESK + SEIPD v1.
      let aead = rest.length() >= 4 && rest[3] == "aead"
      let armored = @api.encrypt_with_password(data, rest[0], aead~)
      @fs.write_string_to_file(rest[2], armored)
      println("wrote \{rest[2]}")
    }
    "decpass" => {
      check_args(rest.length(), 3)
      let armored = @fs.read_file_to_string(rest[1])
      let plain = @api.decrypt_with_password(armored, rest[0])
      @fs.write_bytes_to_file(rest[2], plain)
      println("wrote \{rest[2]}")
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
      check_args(rest.length(), 3)
      let key_text = @fs.read_file_to_string(rest[0])
      let key = @api.PrivateKey::from_armored(key_text)
      // Snapshot the lock state BEFORE unlocking: unlock clears s2k_usage,
      // so key.is_locked() is false afterwards and must not drive the
      // argument positions (a locked key needs [key, passphrase, in, out]).
      let was_locked = key.is_locked()
      let key = if was_locked { key.unlock(rest[1]) } else { key }
      if was_locked {
        check_args(rest.length(), 4)
      }
      let input = if was_locked { rest[2] } else { rest[1] }
      let output = if was_locked { rest[3] } else { rest[2] }
      let data = @api.decrypt_with_private_key(
        @fs.read_file_to_string(input),
        key,
      )
      @fs.write_bytes_to_file(output, data)
      println("wrote \{output}")
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
    _ => usage()
  }
}

///|
fn check_args(got : Int32, want : Int32) -> Unit {
  if got < want {
    usage()
  }
}

///|
fn parse_bits(rest : Array[String], default : Int32) -> Int32 {
  match rest[3:rest.length()].to_owned() {
    [b, ..] => @string.parse_int(b) catch { _ => default }
    _ => default
  }
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
    "  encpass <passphrase> <in> <out> [aead]   (aead = tag-20/GnuPG shape)\n" +
    "  decpass <passphrase> <in> <out>\n" +
    "  encpub <public-key.asc> <in> <out>\n" +
    "  decpriv <secret-key.asc> [passphrase] <in> <out>\n" +
    "  sign <secret-key.asc> <in> <out.sig>\n" +
    "  verify <public-key.asc> <in> <sig.asc>",
  )
}
