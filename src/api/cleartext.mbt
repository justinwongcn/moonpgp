///|
/// Armor-header text name of a hash algorithm (RFC 9580 §9.5 names as
/// used by the `Hash:` armor header of cleartext messages).
pub fn hash_name(id : @primitives.HashId) -> String {
  match id {
    @primitives.Md5 => "MD5"
    @primitives.Sha1 => "SHA1"
    @primitives.Ripemd160 => "RIPEMD160"
    @primitives.Sha224 => "SHA224"
    @primitives.Sha256 => "SHA256"
    @primitives.Sha384 => "SHA384"
    @primitives.Sha512 => "SHA512"
  }
}

///|
/// Canonical form used by cleartext signatures and text signatures:
/// CRLF line endings with trailing spaces/tabs removed per line
/// (RFC 9580 §7.1).
pub fn canonicalize_cleartext(text : String) -> Bytes {
  let normalized = text.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let out : Array[Byte] = []
  // Drop ALL trailing empty elements: the final line ending of the wire
  // body is the separator before the armor (RFC 9580 §7.1) and is not
  // part of the digest. Interior blank lines are preserved.
  let mut end = lines.length()
  while end > 0 && lines[end - 1].is_empty() {
    end = end - 1
  }
  for i in 0..<end {
    if i > 0 {
      out.push(b'\r')
      out.push(b'\n')
    }
    let line = trim_trailing_ws(lines[i])
    let line_bytes = @utf8.encode(line)
    for c in line_bytes {
      out.push(c)
    }
  }
  Bytes::from_array(out)
}

///|
fn trim_trailing_ws(line : StringView) -> StringView {
  let mut end = line.length()
  while end > 0 {
    let c = line[end - 1]
    if c == ' ' || c == '\t' {
      end = end - 1
    } else {
      break
    }
  }
  line[0:end]
}

///|
/// Dash-escape for display: lines starting with "-" (and, per RFC 9580
/// §7.2 SHOULD, "From ") get a "- " prefix.
fn dash_escape_display(canonical : Bytes) -> String {
  let text = match (try? @utf8.decode(canonical.view())) {
    Ok(t) => t
    Err(_) => ""
  }
  let normalized = text.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let buf = StringBuilder::new()
  let n = lines.length()
  for i in 0..<n {
    let line = lines[i]
    if line.has_prefix("-") || line.has_prefix("From ") {
      buf.write_string("- ")
    }
    buf.write_stringview(line)
    if i < n - 1 {
      buf.write_char('\n')
    }
  }
  buf.to_string()
}

///|
/// Reverse dash-escaping on the wire cleartext, returning the raw lines
/// (without line endings).
fn dash_unescape(body : String) -> Array[String] {
  let normalized = body.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let out : Array[String] = []
  for line in lines {
    if line.has_prefix("- ") {
      out.push(line[2:line.length()].to_string())
    } else {
      out.push(line.to_string())
    }
  }
  out
}

///|
/// Create a cleartext signed message (RFC 9580 §7) over UTF-8 text with
/// the default SHA-256 signature of the primary key.
pub fn sign_cleartext(text : String, key : PrivateKey) -> String raise {
  sign_cleartext_with(text, key, @primitives.Sha256)
}

///|
/// Create a cleartext signed message with an explicit hash algorithm.
pub fn sign_cleartext_with(
  text : String,
  key : PrivateKey,
  hash : @primitives.HashId,
) -> String raise {
  let canonical = canonicalize_cleartext(text)
  let sig = make_text_signature(key, canonical, hash)
  let sig_armor = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().view()).view(),
  )
  let displayed = dash_escape_display(canonical)
  let buf = StringBuilder::new()
  buf.write_string("-----BEGIN PGP SIGNED MESSAGE-----\n")
  buf.write_string("Hash: \{hash_name(hash)}\n\n")
  buf.write_string(displayed)
  if not(displayed.has_suffix("\n")) {
    buf.write_char('\n')
  }
  buf.write_string(sig_armor)
  buf.to_string()
}

///|
/// Verify a cleartext signed message. Returns the de-escaped, canonical
/// cleartext and the verification status against `verifier`.
pub fn verify_cleartext(
  message : String,
  verifier : PublicKey,
) -> (String, VerifyStatus) raise {
  let lines : Array[StringView] = message.split("\n").collect()
  let n = lines.length()
  let mut i = 0
  // Skip to the BEGIN marker.
  while i < n && not(lines[i].has_prefix("-----BEGIN PGP SIGNED MESSAGE-----")) {
    i = i + 1
  }
  guard i < n else {
    raise @error.PgpError::PgpError(msg="api: no cleartext signed message")
  }
  i = i + 1
  // Hash armor headers until the empty line; only Hash headers are legal.
  let mut hash_algo : @primitives.HashId? = None
  while i < n && lines[i] != "" {
    let line = lines[i]
    let is_hash = line.has_prefix("Hash:") || line.has_prefix("hash:")
    guard is_hash else {
      raise @error.PgpError::PgpError(
        msg="api: illegal armor header in cleartext message",
      )
    }
    let value = line[5:line.length()].to_string()
    for name in value.split(",").collect() {
      let t = name.trim_space().to_string()
      match hash_id_by_name(t) {
        Some(h) => hash_algo = Some(h)
        None => ()
      }
    }
    i = i + 1
  }
  guard i < n else {
    raise @error.PgpError::PgpError(msg="api: truncated cleartext message")
  }
  i = i + 1
  // Dash-escaped cleartext until the signature armor begins. The line
  // ending before the armor is not part of the signed text.
  let body = StringBuilder::new()
  while i < n && not(lines[i].has_prefix("-----BEGIN PGP SIGNATURE-----")) {
    let line = lines[i]
    if line.has_prefix("- ") {
      body.write_stringview(line[2:line.length()])
    } else {
      if line.has_prefix("-") {
        // Per RFC 9580 §7.2 this SHOULD produce a warning; treat as data.
      }
      body.write_stringview(line)
    }
    body.write_char('\n')
    i = i + 1
  }
  guard i < n else {
    raise @error.PgpError::PgpError(
      msg="api: no signature in cleartext message",
    )
  }
  // Reassemble the canonical cleartext: the trailing "\n" written per
  // line is exactly the text's own line ending (the wire separator was
  // the armor begin line, excluded above).
  let cleartext_raw = body.to_string()
  let canonical = canonicalize_cleartext(cleartext_raw)
  // The signature armor continues from here.
  let rest = StringBuilder::new()
  while i < n {
    rest.write_stringview(lines[i])
    rest.write_char('\n')
    i = i + 1
  }
  let sig_block = @armor.decode(rest.to_string())
  guard sig_block.armor_type() == @armor.Signature else {
    raise @error.PgpError::PgpError(
      msg="api: cleartext message has no signature armor",
    )
  }
  let packets = @packet.parse_packets(@armor.ArmorBlock::data(sig_block).view())
  let mut sig : @packet.SignaturePacket? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().view()))
      break
    }
  }
  match sig {
    Some(s) => {
      let status = verify_signature_packet(s, canonical, verifier)
      let text = match (try? @utf8.decode(canonical.view())) {
        Ok(t) => t
        Err(_) => ""
      }
      (text, status)
    }
    None =>
      raise @error.PgpError::PgpError(
        msg="api: no signature packet in cleartext message",
      )
  }
}

///|
fn hash_id_by_name(name : String) -> @primitives.HashId? {
  match name.to_lower() {
    "md5" => Some(@primitives.Md5)
    "sha1" => Some(@primitives.Sha1)
    "ripemd160" => Some(@primitives.Ripemd160)
    "sha224" => Some(@primitives.Sha224)
    "sha256" => Some(@primitives.Sha256)
    "sha384" => Some(@primitives.Sha384)
    "sha512" => Some(@primitives.Sha512)
    _ => None
  }
}
