///|
/// Armor-header text name of a hash algorithm (RFC 9580 §9.5 names as
/// used by the `Hash:` armor header of cleartext messages).
fn hash_name(id : @primitives.HashId) -> String {
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
fn canonicalize_cleartext(text : String) -> Bytes {
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
  let text = @utf8.decode_lossy(canonical.exact_view())
  let normalized = text.replace_all(old="\r\n", new="\n")
  let lines : Array[StringView] = normalized.split("\n").collect()
  let buf = StringBuilder()
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
/// Create a cleartext signed message (RFC 9580 §7) over UTF-8 text with
/// the default SHA-256 signature of the primary key.
///
/// `created` is the signature creation time in seconds since 1970; without
/// it the current time is used (see `sign_detached`).
pub fn sign_cleartext(
  text : String,
  key : PrivateKey,
  created? : Int32,
) -> String raise {
  sign_cleartext_with(text, key, @primitives.Sha256, created?)
}

///|
/// Create a cleartext signed message with an explicit hash algorithm.
pub fn sign_cleartext_with(
  text : String,
  key : PrivateKey,
  hash : @primitives.HashId,
  created? : Int32,
) -> String raise {
  let canonical = canonicalize_cleartext(text)
  let sig = make_text_signature(key, canonical, hash, created?)
  let sig_armor = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  let displayed = dash_escape_display(canonical)
  let buf = StringBuilder()
  buf.write_string("-----BEGIN PGP SIGNED MESSAGE-----\n")
  buf.write_string("Hash: \{hash_name(hash)}\n\n")
  buf.write_string(displayed)
  if !displayed.has_suffix("\n") {
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
  while i < n && !lines[i].has_prefix("-----BEGIN PGP SIGNED MESSAGE-----") {
    i = i + 1
  }
  guard i < n else { @error.fail("api: no cleartext signed message") }
  i = i + 1
  // Hash armor headers until the empty line; only Hash headers are legal.
  // The values themselves are informational; the signature packet carries
  // the authoritative hash algorithm.
  while i < n && lines[i] != "" {
    let line = lines[i]
    let is_hash = line.has_prefix("Hash:") || line.has_prefix("hash:")
    guard is_hash else {
      @error.fail("api: illegal armor header in cleartext message")
    }
    // The Hash: header value is informational — the digest algorithms come
    // from the signature packets themselves — so there is nothing to parse
    // here (unknown names are tolerated, RFC 9580 §7.2).
    i = i + 1
  }
  guard i < n else { @error.fail("api: truncated cleartext message") }
  i = i + 1
  // Dash-escaped cleartext until the signature armor begins. The line
  // ending before the armor is not part of the signed text.
  let body = StringBuilder()
  while i < n && !lines[i].has_prefix("-----BEGIN PGP SIGNATURE-----") {
    let line = lines[i]
    if line.has_prefix("- ") {
      body.write_stringview(line[2:line.length()])
    } else {
      // A bare "-" (not a dash-space escape) is treated as data; RFC 9580
      // §7.2 says this SHOULD produce a warning.
      body.write_stringview(line)
    }
    body.write_char('\n')
    i = i + 1
  }
  guard i < n else { @error.fail("api: no signature in cleartext message") }
  // Reassemble the canonical cleartext: the trailing "\n" written per
  // line is exactly the text's own line ending (the wire separator was
  // the armor begin line, excluded above).
  let cleartext_raw = body.to_string()
  let canonical = canonicalize_cleartext(cleartext_raw)
  // The signature armor continues from here.
  let rest = StringBuilder()
  while i < n {
    rest.write_stringview(lines[i])
    rest.write_char('\n')
    i = i + 1
  }
  let sig_block = @armor.decode(rest.to_string())
  guard sig_block.armor_type() == @armor.Signature else {
    @error.fail("api: cleartext message has no signature armor")
  }
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(sig_block).exact_view(),
  )
  let mut sig : @packet.SignaturePacket? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().exact_view()))
      break
    }
  }
  match sig {
    Some(s) => {
      let status = verify_signature_packet(s, canonical, verifier)
      // Lossy on purpose (S9): `canonical` is assembled from String
      // pieces via @utf8.encode, which never emits invalid UTF-8 — decode
      // cannot fail, and a silent "" fallback would desync the returned
      // text from the verified bytes. Lossy makes that invariant explicit
      // instead of trapping.
      let text = @utf8.decode_lossy(canonical.exact_view())
      (text, status)
    }
    None => @error.fail("api: no signature packet in cleartext message")
  }
}
