///|
/// moonpgp — OpenPGP mail encryption demo CLI.
///
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
  let rest : Array[String] = args[2:args.length()].to_array()
  match (try? run(args[1], rest)) {
    Ok(_) => ()
    Err(e) => {
      println("error: \{e}")
      abort("command failed")
    }
  }
}

///|
fn run(command : String, rest : Array[String]) -> Unit raise {
  if command == "keygen" {
    check_args(rest.length(), 3)
    let key = @api.generate_key(rest[0], bits=parse_bits(rest, 1024))
    @fs.write_string_to_file(rest[1], key.to_armored())
    @fs.write_string_to_file(rest[2], key.to_public().to_armored())
    println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    return
  }
  if command == "edkeygen" {
    check_args(rest.length(), 3)
    let key = @api.generate_ed25519_key(rest[0])
    @fs.write_string_to_file(rest[1], key.to_armored())
    @fs.write_string_to_file(rest[2], key.to_public().to_armored())
    println("wrote \{rest[1]} (secret) and \{rest[2]} (public)")
    return
  }
  if command == "encpass" {
    check_args(rest.length(), 3)
    let data = @fs.read_file_to_bytes(rest[1])
    let armored = @api.encrypt_with_password(data, rest[0])
    @fs.write_string_to_file(rest[2], armored)
    println("wrote \{rest[2]}")
    return
  }
  if command == "decpass" {
    check_args(rest.length(), 3)
    let armored = @fs.read_file_to_string(rest[1])
    let plain = @api.decrypt_with_password(armored, rest[0])
    @fs.write_bytes_to_file(rest[2], plain)
    println("wrote \{rest[2]}")
    return
  }
  if command == "encpub" {
    check_args(rest.length(), 3)
    let key = @api.PublicKey::from_armored(@fs.read_file_to_string(rest[0]))
    let data = @fs.read_file_to_bytes(rest[1])
    let armored = @api.encrypt_to_recipients(data, [key])
    @fs.write_string_to_file(rest[2], armored)
    println("wrote \{rest[2]}")
    return
  }
  if command == "decpriv" {
    check_args(rest.length(), 3)
    let key_text = @fs.read_file_to_string(rest[0])
    let key = @api.PrivateKey::from_armored(key_text)
    let key = if key.is_locked() { key.unlock(rest[1]) } else { key }
    let input = if key.is_locked() { rest[2] } else { rest[1] }
    let output = if key.is_locked() { rest[3] } else { rest[2] }
    let data = @api.decrypt_with_private_key(
      @fs.read_file_to_string(input),
      key,
    )
    @fs.write_bytes_to_file(output, data)
    println("wrote \{output}")
    return
  }
  if command == "sign" {
    check_args(rest.length(), 3)
    let key = @api.PrivateKey::from_armored(@fs.read_file_to_string(rest[0]))
    let data = @fs.read_file_to_bytes(rest[1])
    let sig = @api.sign_detached(data.view(), key)
    @fs.write_string_to_file(rest[2], sig)
    println("wrote \{rest[2]}")
    return
  }
  if command == "verify" {
    check_args(rest.length(), 3)
    let key = @api.PublicKey::from_armored(@fs.read_file_to_string(rest[0]))
    let data = @fs.read_file_to_bytes(rest[1])
    let sig = @fs.read_file_to_string(rest[2])
    match @api.verify_detached(data.view(), sig, key) {
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
    }
    return
  }
  usage()
}

///|
fn check_args(got : Int, want : Int) -> Unit {
  if got < want {
    usage()
  }
}

///|
fn parse_bits(rest : Array[String], default : Int) -> Int {
  match rest[3:rest.length()].to_array() {
    [b, ..] =>
      match (try? @string.parse_int(b)) {
        Ok(v) => v
        Err(_) => default
      }
    _ => default
  }
}

///|
fn usage() -> Unit {
  println(
    "usage:\n" +
    "  keygen \"Name <me@example.com>\" key.asc pub.asc [bits]\n" +
    "  edkeygen \"Name <me@example.com>\" key.asc pub.asc\n" +
    "  encpass <passphrase> <in> <out>\n" +
    "  decpass <passphrase> <in> <out>\n" +
    "  encpub <public-key.asc> <in> <out>\n" +
    "  decpriv <secret-key.asc> [passphrase] <in> <out>\n" +
    "  sign <secret-key.asc> <in> <out.sig>\n" +
    "  verify <public-key.asc> <in> <sig.asc>",
  )
  abort("missing arguments")
}
