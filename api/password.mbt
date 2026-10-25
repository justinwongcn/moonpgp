///|
/// Encrypt plaintext to a passphrase. Produces an armored PGP MESSAGE with
/// a v4 SKESK (iterated+salted S2K, AES-256 session key wrapped in CFB)
/// followed by a v1 SEIPD packet holding the literal data.
pub fn encrypt_with_password(
  plaintext : BytesView,
  passphrase : String,
  file_name? : String,
  aead~ : Bool = false,
  argon2~ : Bool = false,
  argon2_memory_exp~ : Int32 = 16,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  if aead {
    return seal_aead_with_password(
      plaintext,
      passphrase,
      file_name?,
      argon2~,
      argon2_memory_exp~,
      compress?,
    )
  }
  // `argon2` selects the S2K specifier (RFC 9580 §3.7.1.4) and is
  // orthogonal to the SKESK/SEIPD versions: the v4 SKESK form carries any
  // specifier. Ignoring it here (and using iterated SHA-256) would be a
  // silent KDF downgrade.
  let s2k : @s2k.S2k = if argon2 {
    let salt = @primitives.random_bytes(@s2k.ARGON2_SALT_SIZE)
    @s2k.Argon2(salt, 3, 4, argon2_memory_exp)
  } else {
    let salt = @primitives.random_bytes(@s2k.SALT_SIZE)
    @s2k.Iterated(@primitives.Sha256, salt, @s2k.encode_count(S2K_COUNT_TARGET))
  }
  seal_skesk_with_password(plaintext, passphrase, s2k, file_name?, compress?)
}

///|
/// Encrypt plaintext to a passphrase using Argon2id as the S2K specifier
/// (type 4, RFC 9580 §3.7.1.4) — the RFC's recommendation, and the shape of
/// Appendix A.12. The message keeps the v4 SKESK form (CFB with an
/// all-zero IV) plus a v1 SEIPD packet, so every reader that understands
/// Argon2 can consume it.
///
/// `memory_exp` is the exponent of the Argon2 memory size in KiB (default
/// 16 → 64 MiB, go-crypto's default); `passes` and `parallelism` default to
/// t=3, p=4.
pub fn encrypt_with_password_argon2(
  plaintext : BytesView,
  passphrase : String,
  file_name? : String,
  passes~ : Int32 = 3,
  parallelism~ : Int32 = 4,
  memory_exp~ : Int32 = 16,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  let salt = @primitives.random_bytes(@s2k.ARGON2_SALT_SIZE)
  let s2k : @s2k.S2k = @s2k.Argon2(salt, passes, parallelism, memory_exp)
  seal_skesk_with_password(plaintext, passphrase, s2k, file_name?, compress?)
}

///|
/// Encrypt plaintext to a passphrase in the RFC 9580 v6 shape: a v6 SKESK
/// (AEAD + HKDF-SHA256 key separation, §5.3.2) followed by a v2 SEIPD
/// packet (§5.13.2). `argon2` (default true) selects the Argon2id S2K the
/// RFC recommends for v6; set it to false for the much cheaper
/// iterated+salted SHA-256.
pub fn encrypt_with_password_v6(
  plaintext : BytesView,
  passphrase : String,
  file_name? : String,
  aead~ : @cipher.AeadMode = @cipher.Ocb,
  argon2~ : Bool = true,
  passes~ : Int32 = 3,
  parallelism~ : Int32 = 4,
  memory_exp~ : Int32 = 16,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  seal_skesks_v6_with_passwords(
    plaintext,
    [V6Password::{ passphrase, aead, argon2, passes, parallelism, memory_exp, }],
    file_name?,
    compress?,
  )
}

///|
/// One v6 password recipient with its AEAD/S2K options (task 3: the
/// builder's v6 password path; each passphrase gets its own SKESK under
/// the shared session key).
pub(all) struct V6Password {
  passphrase : String
  aead : @cipher.AeadMode
  argon2 : Bool
  passes : Int32
  parallelism : Int32
  memory_exp : Int32
}

///|
/// Seal to SEVERAL passphrases in the v6 shape: one session key, one v6
/// SKESK per passphrase (each with its own salt and S2K options), one v2
/// SEIPD payload.
fn seal_skesks_v6_with_passwords(
  plaintext : BytesView,
  entries : Array[V6Password],
  file_name? : String,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  guard !entries.is_empty() else {
    @error.fail("api: encryption requires at least one passphrase")
  }
  // The payload's AEAD mode is one per message (v2 SEIPD); every SKESK's
  // associated data must name the same pair.
  for e in entries {
    guard e.aead.number() == entries[0].aead.number() else {
      @error.fail("api: all v6 passphrase recipients must share one AEAD mode")
    }
  }
  let algo = @primitives.Aes256
  let session_key = @primitives.random_bytes(SESSION_KEY_SIZE)
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let seipd = seal_seipd_v2(
    algo,
    entries[0].aead,
    SEIPD_V2_CHUNK_OCTET,
    session_key,
    maybe_compress_inner(literal_wire, compress?).exact_view(),
  )
  let w = @packet.Writer::new()
  for e in entries {
    let s2k : @s2k.S2k = if e.argon2 {
      @s2k.Argon2(
        @primitives.random_bytes(@s2k.ARGON2_SALT_SIZE),
        e.passes,
        e.parallelism,
        e.memory_exp,
      )
    } else {
      @s2k.Iterated(
        @primitives.Sha256,
        @primitives.random_bytes(@s2k.SALT_SIZE),
        @s2k.encode_count(S2K_COUNT_TARGET),
      )
    }
    let cipher_algo = algo.number()
    let aead_algo = e.aead.number()
    let ad = Bytes::from_array([
      0xC3,
      6,
      cipher_algo.to_byte(),
      aead_algo.to_byte(),
    ])
    let kek = s2k.derive_key(
      @primitives.utf8_bytes(e.passphrase).exact_view(),
      algo.key_size(),
    )
    let dek = @primitives.hkdf_sha256(kek, Bytes::new(0), ad, algo.key_size())
    let bc = @primitives.new_block_cipher(algo, dek.exact_view())
    let nonce = @primitives.random_bytes(e.aead.iv_length())
    let esk = aead_seal_session_key(
      bc,
      e.aead,
      nonce.exact_view(),
      ad.exact_view(),
      session_key.exact_view(),
    )
    let skesk : @packet.SkeskPacket = {
      version: 6,
      cipher_algo,
      aead_algo,
      s2k,
      iv: nonce,
      encrypted_session_key: esk,
    }
    w.bytes(
      @packet.serialize_packet(@packet.Skesk, skesk.to_body().exact_view()).exact_view(),
    )
  }
  w.bytes(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().exact_view()).exact_view(),
  )
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// Wrap `session_key` with `s2k` into a v4 SKESK and seal the literal data
/// with a v1 SEIPD packet. Shared by every passphrase-encryption entry
/// point; the caller supplies the already-parameterised S2K.
fn seal_skesk_with_password(
  plaintext : BytesView,
  passphrase : String,
  s2k : @s2k.S2k,
  file_name? : String,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  let session_key = @primitives.random_bytes(SESSION_KEY_SIZE)
  let skesk = build_skesk(session_key.exact_view(), passphrase, s2k)
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let seipd_ciphertext = seal_seipd(
    session_key.exact_view(),
    maybe_compress_inner(literal_wire, compress?).exact_view(),
  )
  let w = @packet.Writer::new()
  w.u8(0xC0 | @packet.Skesk.number())
  let skesk_body = skesk.to_body()
  write_packet_length(w, skesk_body.length())
  w.bytes(skesk_body.exact_view())
  w.u8(0xC0 | @packet.Seipd.number())
  write_packet_length(w, seipd_ciphertext.length() + 1)
  w.u8(1)
  w.bytes(seipd_ciphertext.exact_view())
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// Encrypt to SEVERAL passphrases (N4): one fresh session key sealed by
/// one SKESK per passphrase (each with its own salt), then a single v1
/// SEIPD over the literal data — the multi-recipient passphrase shape
/// `unwrap_skesk` expects when it walks the SKESKs in turn.
fn seal_skesks_with_passwords(
  plaintext : BytesView,
  passphrases : Array[String],
  file_name? : String,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  guard !passphrases.is_empty() else {
    @error.fail("api: encryption requires at least one passphrase")
  }
  let session_key = @primitives.random_bytes(SESSION_KEY_SIZE)
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let seipd_ciphertext = seal_seipd(
    session_key.exact_view(),
    maybe_compress_inner(literal_wire, compress?).exact_view(),
  )
  let w = @packet.Writer::new()
  for passphrase in passphrases {
    let s2k : @s2k.S2k = @s2k.Iterated(
      @primitives.Sha256,
      @primitives.random_bytes(@s2k.SALT_SIZE),
      @s2k.encode_count(S2K_COUNT_TARGET),
    )
    let skesk = build_skesk(session_key.exact_view(), passphrase, s2k)
    w.bytes(
      @packet.serialize_packet(@packet.Skesk, skesk.to_body().exact_view()).exact_view(),
    )
  }
  w.bytes(
    @packet.serialize_packet(
      @packet.Seipd,
      Bytes::from_array([1]).add(seipd_ciphertext).exact_view(),
    ).exact_view(),
  )
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// Decrypt an (optionally armored) message using a passphrase. Returns the
/// literal data. Compressed packets are transparently decompressed.
pub fn decrypt_with_password(
  message : String,
  passphrase : String,
  argon2_max_memory_kib~ : Int32 = @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
  max_decompressed~ : Int32 = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> Bytes raise {
  let armored = @armor.decode(message)
  decrypt_binary_with_password(
    @armor.ArmorBlock::data(armored),
    passphrase,
    argon2_max_memory_kib~,
    max_decompressed~,
  )
}

///|
/// Same as `decrypt_with_password` but takes binary packet data.
///
/// Every SKESK in the stream is tried until one both unwraps AND opens the
/// message payload (N4): a v4 SKESK has no integrity check of its own, so
/// a wrong passphrase can unwrap to structurally plausible garbage whose
/// wrongness only surfaces at the SEIPD MDC — the retry must therefore
/// span the payload decryption, not just the unwrap.
pub fn decrypt_binary_with_password(
  data : BytesView,
  passphrase : String,
  argon2_max_memory_kib~ : Int32 = @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
  max_decompressed~ : Int32 = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> Bytes raise {
  let packets = @packet.parse_packets(data)
  let mut last_error : String? = None
  for p in packets {
    if p.tag() == @packet.Skesk {
      let skesk = @packet.SkeskPacket::parse(p.body().exact_view())
      let opened : Bytes? = try {
        let (msg_algo, session_key, skesk_version) = unwrap_one_skesk(
          skesk, passphrase, argon2_max_memory_kib,
        )
        Some(
          open_password_payload(
            packets, msg_algo, session_key, skesk_version, max_decompressed,
          ),
        )
      } catch {
        e => {
          last_error = Some(e.to_string())
          None
        }
      }
      if opened is Some(plain) {
        return plain
      }
    }
  }
  match last_error {
    Some(msg) =>
      @error.fail("api: no SKESK in the message matched the passphrase: \{msg}")
    None => @error.fail("api: no SKESK packet found")
  }
}

///|
/// Open the encrypted payload of a password message with one unwrapped
/// session key: the tag-20 4880bis AEAD container, or the v1/v2 SEIPD
/// whose version must align with the SKESK's (Table 26).
fn open_password_payload(
  packets : Array[@packet.RawPacket],
  msg_algo : @primitives.CipherAlgo,
  session_key : Bytes,
  skesk_version : Int32,
  max_decompressed : Int32,
) -> Bytes raise {
  for p in packets {
    if p.tag() == @packet.AeadEncData {
      let aead = @packet.AeadPacket::parse(p.body().exact_view())
      let algo = match @primitives.cipher_algo_of_number(aead.cipher_algo()) {
        Some(a) => a
        None =>
          @error.fail(
            "api: unsupported AEAD cipher algorithm \{aead.cipher_algo()}",
          )
      }
      let mode = match @cipher.aead_mode_of_number(aead.aead_algo()) {
        Some(m) => m
        None => @error.fail("api: unknown AEAD algorithm \{aead.aead_algo()}")
      }
      guard session_key.length() == algo.key_size() else {
        @error.fail("api: session key length does not match the AEAD cipher")
      }
      let bc = @primitives.new_block_cipher(algo, session_key.exact_view())
      // Associated-data header: 0xD4 | version | cipher | aead | chunk octet.
      let header5 = Bytes::from_array([
        0xD4,
        aead.version().to_byte(),
        aead.cipher_algo().to_byte(),
        aead.aead_algo().to_byte(),
        aead.chunk_octet().to_byte(),
      ])
      let inner = @cipher.aead_open(
        bc,
        mode,
        header5.exact_view(),
        aead.iv().exact_view(),
        aead.chunk_octet(),
        aead.ciphertext().exact_view(),
      )
      return extract_literal(inner, max_decompressed)
    }
    if p.tag() == @packet.Seipd {
      let seipd = @packet.SeipdPacket::parse(p.body().exact_view())
      // RFC 9580 §10.3.2.1 (Table 26): a v4 SKESK pairs with a v1 SEIPD and
      // a v6 SKESK with a v2 SEIPD; a mismatched ESK version must be
      // discarded. (The tag-20 4880bis AEAD container above is not part of
      // RFC 9580 and keeps its lenient handling for GnuPG interop.)
      guard (seipd.version == 2) == (skesk_version == 6) else {
        @error.fail(
          "api: SKESK version \{skesk_version} does not align with SEIPD version \{seipd.version}",
        )
      }
      if seipd.version == 2 {
        return decrypt_seipd_v2(seipd, session_key, max_decompressed)
      }
      guard seipd.version == 1 else {
        @error.fail("api: unsupported SEIPD version \{seipd.version}")
      }
      // The SEIPD cipher is the one named inside the unwrapped session key,
      // which need not match the SKESK's wrapping cipher (RFC 9580 §5.3.1).
      guard session_key.length() == msg_algo.key_size() else {
        @error.fail("api: session key length does not match the message cipher")
      }
      let bc = @primitives.new_block_cipher(msg_algo, session_key.exact_view())
      let inner = @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.exact_view())
      return extract_literal(inner, max_decompressed)
    }
  }
  @error.fail("api: no encrypted data packet found")
}

///|
const SESSION_KEY_SIZE : Int32 = 32

///|
/// S2K hashed-material target for passphrase derivation: 56,623,104 octets
/// (~54 MiB), gpg's default count (byte 251). The previous 1 MiB was
/// ~50x lighter than gpg's own interactive cost.
const S2K_COUNT_TARGET : Int32 = 56623104

///|
fn write_packet_length(w : @packet.Writer, length : Int32) -> Unit {
  if length < 192 {
    w.u8(length)
  } else if length < 8384 {
    let enc = length - 192 + 192 * 256
    w.u8(enc >> 8)
    w.u8(enc)
  } else {
    w.u8(255)
    w.u32(length)
  }
}

///|
/// Build a v4 SKESK whose S2K-derived key wraps `[algo || session key]` with
/// CFB under an all-zero IV (RFC 9580 §5.3.1: an all-zero IV requires a
/// salted or Argon2 specifier).
fn build_skesk(
  session_key : BytesView,
  passphrase : String,
  s2k : @s2k.S2k,
) -> @packet.SkeskPacket raise {
  // The S2K key wraps [algo byte || session key] with CFB, zero IV.
  let wrapping_key = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    SESSION_KEY_SIZE,
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    wrapping_key.exact_view(),
  )
  let plain = Bytes::from_array([@primitives.Aes256.number().to_byte()]).add(
    session_key.to_owned(),
  )
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(16, b'\x00').exact_view(),
    plain.exact_view(),
  )
  @packet.SkeskPacket::{
    version: 4,
    cipher_algo: @primitives.Aes256.number(),
    aead_algo: 0,
    s2k,
    iv: Bytes::new(0),
    encrypted_session_key: esk,
  }
}

///|
/// Recover the session key and its message cipher algorithm from the
/// packet stream's SKESK. Every SKESK in the stream is tried in order
/// until one yields to `passphrase` (N4): a message sealed to several
/// passphrases carries one SKESK per passphrase, and the matching one
/// need not be first. (A v4 SKESK whose wrong-passphrase garbage happens
/// to decode as a valid cipher octet still slips through to fail at the
/// SEIPD integrity check — it has no checksum of its own.)
fn unwrap_skesk(
  packets : Array[@packet.RawPacket],
  passphrase : String,
  argon2_max_memory_kib : Int32,
) -> (@primitives.CipherAlgo, Bytes, Int32) raise {
  let mut last_error : String? = None
  for p in packets {
    if p.tag() == @packet.Skesk {
      let skesk = @packet.SkeskPacket::parse(p.body().exact_view())
      let unwrapped : (@primitives.CipherAlgo, Bytes, Int32)? = Some(
        unwrap_one_skesk(skesk, passphrase, argon2_max_memory_kib),
      ) catch {
        e => {
          last_error = Some(e.to_string())
          None
        }
      }
      if unwrapped is Some(result) {
        return result
      }
    }
  }
  match last_error {
    Some(msg) =>
      @error.fail("api: no SKESK in the message matched the passphrase: \{msg}")
    None => @error.fail("api: no SKESK packet found")
  }
}

///|
/// Unwrap a single SKESK. Any raise means "this SKESK does not match the
/// passphrase", which the caller treats as a reason to try the next one.
fn unwrap_one_skesk(
  skesk : @packet.SkeskPacket,
  passphrase : String,
  argon2_max_memory_kib : Int32,
) -> (@primitives.CipherAlgo, Bytes, Int32) raise {
  let algo = match @primitives.cipher_algo_of_number(skesk.cipher_algo()) {
    Some(a) => a
    None =>
      @error.fail("api: unsupported cipher algorithm \{skesk.cipher_algo()}")
  }
  let pass = @primitives.utf8_bytes(passphrase)
  if skesk.version() == 6 {
    // RFC 9580 §5.3.2: the same HKDF-SHA256 key separation as a
    // usage-253 secret key, with info/AD = tag | version | cipher |
    // aead, and the session key sealed alone (no algorithm octet).
    let kek = skesk
      .s2k()
      .derive_key_capped(
        pass.exact_view(),
        algo.key_size(),
        argon2_max_memory_kib,
      )
    let mode = match @cipher.aead_mode_of_number(skesk.aead_algo()) {
      Some(m) => m
      None =>
        @error.fail("api: unknown SKESK AEAD algorithm \{skesk.aead_algo()}")
    }
    let ad = Bytes::from_array([
      0xC3,
      6,
      skesk.cipher_algo().to_byte(),
      skesk.aead_algo().to_byte(),
    ])
    let dek = @primitives.hkdf_sha256(kek, Bytes::new(0), ad, algo.key_size())
    let bc = @primitives.new_block_cipher(algo, dek.exact_view())
    let key = aead_open_session_key(
      bc,
      mode,
      skesk.iv().exact_view(),
      ad.exact_view(),
      skesk.encrypted_session_key().exact_view(),
    )
    guard key.length() == algo.key_size() else {
      @error.fail("api: AEAD-wrapped session key has the wrong length")
    }
    return (algo, key, skesk.version())
  }
  if skesk.version() == 5 {
    // v5: the S2K-derived key is the AEAD key directly (no HKDF — the
    // HKDF step belongs to the v6 SKESK); AD = C3 05 cipher aead.
    let kek = skesk
      .s2k()
      .derive_key_capped(
        pass.exact_view(),
        algo.key_size(),
        argon2_max_memory_kib,
      )
    let mode = match @cipher.aead_mode_of_number(skesk.aead_algo()) {
      Some(m) => m
      None =>
        @error.fail("api: unknown SKESK AEAD algorithm \{skesk.aead_algo()}")
    }
    let bc = @primitives.new_block_cipher(algo, kek.exact_view())
    let ad = Bytes::from_array([
      0xC3,
      5,
      skesk.cipher_algo().to_byte(),
      skesk.aead_algo().to_byte(),
    ])
    let key = aead_open_session_key(
      bc,
      mode,
      skesk.iv().exact_view(),
      ad.exact_view(),
      skesk.encrypted_session_key().exact_view(),
    )
    guard key.length() == algo.key_size() else {
      @error.fail("api: AEAD-wrapped session key has the wrong length")
    }
    return (algo, key, skesk.version())
  }
  if skesk.encrypted_session_key().length() == 0 {
    return (
      algo,
      skesk
      .s2k()
      .derive_key_capped(
        pass.exact_view(),
        algo.key_size(),
        argon2_max_memory_kib,
      ),
      skesk.version(),
    )
  }
  let bc = @primitives.new_block_cipher(
    algo,
    skesk
    .s2k()
    .derive_key_capped(
      pass.exact_view(),
      algo.key_size(),
      argon2_max_memory_kib,
    )
    .exact_view(),
  )
  let wrapped = @cipher.cfb_decrypt(
    bc,
    Bytes::make(16, b'\x00').exact_view(),
    skesk.encrypted_session_key().exact_view(),
  )
  guard wrapped.length() >= 1 else { @error.fail("api: empty session key") }
  // The wrapped value carries the message cipher algorithm octet, which
  // may differ from the SKESK's own wrapping cipher (RFC 9580 §5.3.1).
  let inner_algo = match
    @primitives.cipher_algo_of_number(wrapped[0].to_int()) {
    Some(a) => a
    None => @error.fail("api: unsupported inner cipher algorithm")
  }
  guard wrapped.length() - 1 == inner_algo.key_size() else {
    @error.fail("api: session key length mismatch")
  }
  return (inner_algo, wrapped[1:wrapped.length()].to_owned(), skesk.version())
}

///|
fn seal_seipd(session_key : BytesView, inner : BytesView) -> Bytes raise {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session_key.exact_view(),
  )
  @cipher.seipd_v1_encrypt(bc, inner)
}

///|
/// AEAD message builder (the --force-aead shape GnuPG 2.4 consumes):
/// a v5 SKESK holding the OCB-sealed session key, then a tag-20 AEAD
/// packet over the literal data. AES-256 + OCB, chunk octet 14 (1 MiB).
fn seal_aead_with_password(
  plaintext : BytesView,
  passphrase : String,
  file_name? : String,
  argon2~ : Bool = false,
  argon2_memory_exp~ : Int32 = 16,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  let cipher_algo = @primitives.Aes256.number()
  let aead_algo = @cipher.Ocb.number()
  let session_key = @primitives.random_bytes(SESSION_KEY_SIZE)
  let s2k : @s2k.S2k = if argon2 {
    @s2k.Argon2(
      @primitives.random_bytes(@s2k.ARGON2_SALT_SIZE),
      3,
      4,
      argon2_memory_exp,
    )
  } else {
    let salt = @primitives.random_bytes(@s2k.SALT_SIZE)
    let count_byte = @s2k.encode_count(S2K_COUNT_TARGET)
    @s2k.Iterated(@primitives.Sha256, salt, count_byte)
  }
  let pass = @primitives.utf8_bytes(passphrase)
  let kek = s2k.derive_key(pass.exact_view(), SESSION_KEY_SIZE)
  let kek_bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    kek.exact_view(),
  )
  let esk_ad = Bytes::from_array([
    0xC3,
    5,
    cipher_algo.to_byte(),
    aead_algo.to_byte(),
  ])
  let esk_iv = @primitives.random_bytes(15)
  let esk = @cipher.ocb_encrypt(
    kek_bc,
    esk_iv.exact_view(),
    esk_ad.exact_view(),
    session_key.exact_view(),
  )
  let skesk : @packet.SkeskPacket = {
    version: 5,
    cipher_algo,
    aead_algo,
    s2k,
    iv: esk_iv,
    encrypted_session_key: esk,
  }
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let literal_wire = maybe_compress_inner(literal_wire, compress?)
  let data_bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session_key.exact_view(),
  )
  let data_iv = @primitives.random_bytes(15)
  let chunk_octet = 14
  let header5 = Bytes::from_array([
    0xD4,
    1,
    cipher_algo.to_byte(),
    aead_algo.to_byte(),
    chunk_octet.to_byte(),
  ])
  let body = @cipher.aead_seal(
    data_bc,
    @cipher.Ocb,
    header5.exact_view(),
    data_iv.exact_view(),
    chunk_octet,
    literal_wire.exact_view(),
  )
  let aead : @packet.AeadPacket = {
    version: 1,
    cipher_algo,
    aead_algo,
    chunk_octet,
    iv: data_iv,
    ciphertext: body,
  }
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.AeadEncData, aead.to_body().exact_view()).exact_view(),
  )
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// Walk a decrypted packet stream to the literal data, decompressing on
/// the way. Trailing signature packets (one-pass) are consumed by later
/// layers. Decompressed output draws from a cumulative budget (S03): the
/// iteration cap bounds nesting depth, the budget bounds total expansion.
fn extract_literal(inner : BytesView, max_decompressed : Int32) -> Bytes raise {
  let mut stream = inner
  let mut budget = max_decompressed
  // At most two nesting levels: SEIPD -> compressed -> literal. A
  // one-pass signature packet may precede the data.
  for _ in 0..<3 {
    let ps = @packet.parse_packets(stream)
    if ps.is_empty() {
      @error.fail("api: empty inner packet stream")
    }
    let tag = ps[0].tag()
    if tag == @packet.Literal {
      return @packet.LiteralPacket::parse(ps[0].body().exact_view()).data()
    }
    if tag == @packet.OnePassSig {
      // Re-parse the rest after the OPS packet.
      if ps.length() > 1 {
        let w = @packet.Writer::new()
        for p in ps[1:ps.length()] {
          w.bytes(
            @packet.serialize_packet(p.tag(), p.body().exact_view()).exact_view(),
          )
        }
        stream = w.to_bytes().exact_view()
        continue
      }
      @error.fail("api: one-pass signature with no data")
    }
    if tag == @packet.Compressed {
      let comp = @packet.CompressedPacket::parse(ps[0].body().exact_view())
      match comp.algo {
        0 => stream = comp.data.exact_view()
        _ => {
          let cap = if budget < max_decompressed {
            budget
          } else {
            max_decompressed
          }
          let out = decompress_payload(comp, cap)
          budget = budget - out.length()
          stream = out.exact_view()
        }
      }
      continue
    }
    @error.fail(
      "api: expected literal or compressed packet, got tag \{tag.number()}",
    )
  }
  @error.fail("api: literal data not found")
}

///|
/// AEAD-open a wrapped session key with any supported mode.
fn aead_open_session_key(
  bc : &@primitives.BlockCipher,
  mode : @cipher.AeadMode,
  nonce : BytesView,
  ad : BytesView,
  cipher : BytesView,
) -> Bytes raise {
  match mode {
    @cipher.Ocb => @cipher.ocb_decrypt(bc, nonce, ad, cipher)
    @cipher.Gcm => @cipher.gcm_decrypt(bc, nonce, ad, cipher)
    @cipher.Eax => @cipher.eax_decrypt(bc, nonce, ad, cipher)
  }
}

///|
/// AEAD-seal a session key with any supported mode.
fn aead_seal_session_key(
  bc : &@primitives.BlockCipher,
  mode : @cipher.AeadMode,
  nonce : BytesView,
  ad : BytesView,
  plain : BytesView,
) -> Bytes raise {
  match mode {
    @cipher.Ocb => @cipher.ocb_encrypt(bc, nonce, ad, plain)
    @cipher.Gcm => @cipher.gcm_encrypt(bc, nonce, ad, plain)
    @cipher.Eax => @cipher.eax_encrypt(bc, nonce, ad, plain)
  }
}

///|
/// Open a v2 SEIPD packet (RFC 9580 §5.13.2): derive the message key and
/// nonce prefix from the session key and the packet salt, and decrypt the
/// chunked AEAD payload. Returns the raw inner packet stream, so callers
/// that need the signature packets get them too.
fn open_seipd_v2(
  seipd : @packet.SeipdPacket,
  session_key : BytesView,
) -> Bytes raise {
  let algo = @error.require(
    @primitives.cipher_algo_of_number(seipd.cipher_algo()),
    "api: unsupported SEIPD v2 cipher",
  )
  let mode = @error.require(
    @cipher.aead_mode_of_number(seipd.aead_algo()),
    "api: unknown SEIPD v2 AEAD algorithm",
  )
  guard session_key.length() == algo.key_size() else {
    @error.fail("api: session key length does not match the SEIPD v2 cipher")
  }
  let header5 = Bytes::from_array([
    0xD2,
    2,
    seipd.cipher_algo().to_byte(),
    seipd.aead_algo().to_byte(),
    seipd.chunk_octet().to_byte(),
  ])
  let (key, iv) = @cipher.seipd_v2_kdf(
    session_key,
    seipd.salt().exact_view(),
    algo.key_size(),
    mode,
    header5.exact_view(),
  )
  let bc = @primitives.new_block_cipher(algo, key.exact_view())
  let inner = @cipher.seipd_v2_open(
    bc,
    mode,
    header5.exact_view(),
    iv.exact_view(),
    seipd.chunk_octet(),
    seipd.ciphertext.exact_view(),
  ) catch {
    _ =>
      @error.fail(
        "api: SEIPD v2 decryption failed (wrong key or corrupted message)",
      )
  }
  inner
}

///|
/// Open a v2 SEIPD packet and extract its literal payload.
fn decrypt_seipd_v2(
  seipd : @packet.SeipdPacket,
  session_key : BytesView,
  max_decompressed : Int32,
) -> Bytes raise {
  extract_literal(open_seipd_v2(seipd, session_key), max_decompressed)
}
