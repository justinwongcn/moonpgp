///|
/// Build a PKESK for one recipient over the session key, choosing the
/// algorithm by the recipient's encryption-capable key packet.
fn create_pkesk(
  enc_key : @packet.PublicKeyPacket,
  session_key : BytesView,
  sym_algo : @primitives.CipherAlgo,
) -> @packet.PkeskPacket raise {
  match enc_key.algo() {
    @packet.X25519 => {
      // §5.1.6: native 32-octet ephemeral key, no algorithm octet and no
      // session-key checksum (the v2 SEIPD names the cipher).
      let (eph, wrapped) = x25519_wrap_session_key(enc_key, session_key)
      {
        version: 6,
        key_id: Bytes::new(0),
        key_version: enc_key.version(),
        fingerprint: enc_key.fingerprint(),
        pub_algo: @packet.X25519,
        encrypted: wrapped,
        ecdh_ephemeral: eph,
      }
    }
    @packet.Ecdh => {
      let (eph, wrapped) = ecdh_wrap_session_key(enc_key, session_key, sym_algo)
      {
        version: 3,
        key_id: enc_key.key_id(),
        key_version: 0,
        fingerprint: Bytes::new(0),
        pub_algo: @packet.Ecdh,
        encrypted: wrapped,
        ecdh_ephemeral: eph,
      }
    }
    a if a.is_rsa() => {
      let rsa = rsa_public_key(enc_key)
      // m = algo(1) || session key || 2-octet checksum, PKCS#1 v1.5.
      let payload = Bytes::from_array([sym_algo.number().to_byte()])
        .add(session_key.to_owned())
        .add(checksum_bytes(@packet.session_key_checksum(session_key)))
      let mpi = rsa.pkcs1_v15_encrypt(payload.exact_view())
      {
        version: 3,
        key_id: enc_key.key_id(),
        key_version: 0,
        fingerprint: Bytes::new(0),
        pub_algo: a,
        encrypted: mpi,
        ecdh_ephemeral: Bytes::new(0),
      }
    }
    _ => @error.fail("api: recipient key algorithm cannot encrypt")
  }
}

///|
/// Recover (symmetric algo id, session key) from a PKESK with the
/// matching unlocked secret key packet.
fn unwrap_pkesk(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> (Int, Bytes) raise {
  match pkesk.pub_algo() {
    @packet.X25519 => x25519_unwrap_session_key(pkesk, sk)
    @packet.Ecdh => ecdh_unwrap_session_key(pkesk, sk)
    a if a.is_rsa() => rsa_unwrap_session_key(pkesk, sk)
    _ =>
      @error.fail(
        "api: unsupported PKESK algorithm \{pkesk.pub_algo().number()}",
      )
  }
}

///|
/// Encrypt plaintext to one or more recipients' public keys. Each
/// recipient gets its own fresh PKESK encoding of the session key
/// (RFC 9580 §5.1.3 requires re-encoding per key). Result: armored PGP
/// MESSAGE of PKESK(s) + SEIPD, v2 for v6 recipients and v1 otherwise.
pub fn encrypt_to_recipients(
  plaintext : BytesView,
  recipients : Array[PublicKey],
  file_name? : String,
) -> String raise {
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  seal_to_recipients(literal_wire, recipients)
}

///|
/// Seal a pre-serialized inner packet stream into PKESK(s) plus a SEIPD
/// container and armor the result. Shared by `encrypt_to_recipients` (inner
/// = the literal packet) and `sign_and_encrypt`'s
/// `encrypt_to_recipients` (inner = the literal packet) and
/// `sign_and_encrypt` (inner = OPS + literal + signature).
///
/// The container version must match the PKESK generation: "The payload
/// following any v6 PKESK or v6 SKESK packet MUST be a v2 SEIPD", and a v2
/// SEIPD must not be preceded by v3 PKESKs (RFC 9580 §5.1.1/§5.1.2, §10.3.2.1).
fn seal_to_recipients(
  inner : BytesView,
  recipients : Array[PublicKey],
) -> String raise {
  guard !recipients.is_empty() else { @error.fail("api: no recipients") }
  // A message cannot mix key generations: v6 PKESKs must precede a v2
  // SEIPD packet and v3 PKESKs a v1 one (RFC 9580 §5.1.1/§5.1.2).
  let v6 = recipients[0].primary.version() >= 6
  for recipient in recipients {
    guard (recipient.primary.version() >= 6) == v6 else {
      @error.fail("api: cannot mix v4 and v6 recipients in one message")
    }
  }
  // RFC 9580 §5.2.3.15/§13.2: every recipient must accept the chosen pair,
  // so take the first recipient's preference order and intersect it with
  // every other recipient's candidate list.
  let (sym_algo, aead_mode) = if v6 {
    pick_v6_ciphersuite(recipients)
  } else {
    (@primitives.Aes256, @cipher.Ocb)
  }
  let session_key = @primitives.random_bytes(sym_algo.key_size())
  let w = @packet.Writer::new()
  for recipient in recipients {
    let enc_key = match recipient.encryption_key() {
      Some(k) => k
      None => @error.fail("api: recipient key cannot encrypt")
    }
    let pkesk = create_pkesk(enc_key, session_key.exact_view(), sym_algo)
    let body = pkesk.to_body()
    w.bytes(
      @packet.serialize_packet(@packet.Pkesk, body.exact_view()).exact_view(),
    )
  }
  let seipd : @packet.SeipdPacket = if v6 {
    seal_seipd_v2(sym_algo, aead_mode, SEIPD_V2_CHUNK_OCTET, session_key, inner)
  } else {
    // v1 SEIPD always uses the v4 profile's mandatory cipher. Built here,
    // not before the branch: a v6 ciphersuite may be AES-128/192, and an
    // eager AES-256 cipher would reject that session-key length.
    let bc = @primitives.new_block_cipher(
      @primitives.Aes256,
      session_key.exact_view(),
    )
    @packet.SeipdPacket::v1(@cipher.seipd_v1_encrypt(bc, inner).exact_view())
  }
  w.bytes(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().exact_view()).exact_view(),
  )
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// The chunk-size octet this library writes for v2 SEIPD packets:
/// 2^(14+6) = 1 MiB (RFC 9580 §5.13.2 forbids values above 16). Internal:
/// it is a writer-side policy knob, not part of the public API.
const SEIPD_V2_CHUNK_OCTET : Int = 14

///|
/// Seal a v2 SEIPD packet (RFC 9580 §5.13.2): fresh 32-octet salt, HKDF
/// message key and nonce, chunked AEAD.
fn seal_seipd_v2(
  algo : @primitives.CipherAlgo,
  mode : @cipher.AeadMode,
  chunk_octet : Int,
  session_key : BytesView,
  plain : BytesView,
) -> @packet.SeipdPacket raise {
  guard session_key.length() == algo.key_size() else {
    @error.fail("api: session key length does not match the SEIPD v2 cipher")
  }
  let salt = @primitives.random_bytes(32)
  let header5 = Bytes::from_array([
    0xD2,
    2,
    algo.number().to_byte(),
    mode.number().to_byte(),
    chunk_octet.to_byte(),
  ])
  let (key, iv) = @cipher.seipd_v2_kdf(
    session_key,
    salt.exact_view(),
    algo.key_size(),
    mode,
    header5.exact_view(),
  )
  let bc = @primitives.new_block_cipher(algo, key.exact_view())
  let ct = @cipher.seipd_v2_seal(
    bc,
    mode,
    header5.exact_view(),
    iv.exact_view(),
    chunk_octet,
    plain,
  )
  {
    version: 2,
    cipher_algo: algo.number(),
    aead_algo: mode.number(),
    chunk_octet,
    salt,
    ciphertext: ct,
  }
}

///|
fn checksum_bytes(sum : Int) -> Bytes {
  Bytes::from_array([(sum >> 8).to_byte(), sum.to_byte()])
}

///|
/// Decrypt a binary message with an unlocked private key. Matches PKESKs
/// against the key's ids (RSA or ECDH), recovers the session key, checks
/// the session-key checksum, and unwraps the SEIPD payload.
pub fn decrypt_binary_with_private_key(
  data : BytesView,
  key : PrivateKey,
) -> Bytes raise {
  let packets = @packet.parse_packets(data)
  let inner = match decrypt_inner_with_key(packets, key) {
    Some(b) => b
    None => @error.fail("api: message is not encrypted to this key")
  }
  extract_literal(inner)
}

///|
/// Match a PKESK in `packets` against `key` — v6 by fingerprint, v3 by key
/// id, over the primary key and the encryption subkey — recover the session
/// key and return the raw inner packet stream of the SEIPD container. `None`
/// means no PKESK belongs to this key; a matched packet that cannot be
/// decrypted raises. Shared by `decrypt_binary_with_private_key` and the
/// sign/decrypt pipeline in `sign.mbt`, so both accept the same messages.
fn decrypt_inner_with_key(
  packets : Array[@packet.RawPacket],
  key : PrivateKey,
) -> Bytes? raise {
  let candidates : Array[@packet.SecretKeyPacket] = [key.primary]
  match key.encryption_subkey {
    Some(sk) => candidates.push(sk)
    None => ()
  }
  for p in packets {
    if p.tag() == @packet.Pkesk {
      let pkesk = @packet.PkeskPacket::parse(p.body().exact_view())
      for sk in candidates {
        let matches = if pkesk.version() == 6 {
          // §5.1.2: a v6 PKESK identifies the recipient by fingerprint.
          let fp = sk.public.fingerprint() catch { _ => Bytes::new(0) }
          pkesk.fingerprint().length() > 0 && fp.equal(pkesk.fingerprint())
        } else {
          let id = sk.public.key_id() catch { _ => Bytes::new(0) }
          id.equal(pkesk.key_id())
        }
        if matches {
          let (algo, session) = unwrap_pkesk(pkesk, sk)
          return Some(
            unwrap_seipd_inner(packets, algo, session, pkesk.version()),
          )
        }
      }
    }
  }
  None
}

///|
/// RSA-decrypt a v3 PKESK with an unlocked RSA secret key. Returns
/// (symmetric algorithm id, session key): the cipher octet is only
/// carried inside the PKCS#1 payload (RFC 9580 §5.1.3), so it must be
/// handed back rather than assumed — GnuPG happily encrypts with
/// `--cipher-algo AES128`, and a v1 SEIPD names no cipher of its own.
fn rsa_unwrap_session_key(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> (Int, Bytes) raise {
  let rsa = rsa_secret_parts(sk)
  let k = rsa.public.octet_length()
  guard pkesk.encrypted().length() <= k else {
    @error.fail("api: PKESK size mismatch")
  }
  // The wire MPI may have lost a leading zero octet; os2ip restores the
  // integer value either way.
  let padded = @primitives.pad_left(pkesk.encrypted().exact_view(), k)
  let payload = rsa.pkcs1_v15_decrypt(padded.exact_view())
  guard payload.length() >= 3 + 16 else {
    @error.fail("api: session key payload too short")
  }
  let algo = payload[0].to_int()
  guard @primitives.cipher_algo_of_number(algo) is Some(_) else {
    @error.fail("api: unexpected session key cipher \{algo}")
  }
  let key_len = payload.length() - 3
  let key = payload[1:1 + key_len]
  let want = (payload[payload.length() - 2].to_int() << 8) |
    payload[payload.length() - 1].to_int()
  guard @packet.session_key_checksum(key.exact_view()) == want else {
    @error.fail("api: session key checksum mismatch")
  }
  (algo, key.to_owned())
}

///|
/// Decrypt the SEIPD container in `packets` and return its raw inner packet
/// stream. A v2 container names its own cipher, so the PKESK/SKESK
/// algorithm id is unused there; a v1 container takes it from the ESK
/// packet because SEIPD v1 carries no cipher of its own.
fn unwrap_seipd_inner(
  packets : Array[@packet.RawPacket],
  algo_id : Int,
  session_key : Bytes,
  esk_version : Int,
) -> Bytes raise {
  for p in packets {
    if p.tag() == @packet.Seipd {
      let seipd = @packet.SeipdPacket::parse(p.body().exact_view())
      // RFC 9580 §10.3.2.1 (Table 26): "An implementation processing an
      // Encrypted Message MUST discard any preceding ESK packet with a
      // version that does not align with the version of the payload."
      // A v6 PKESK pairs with v2 SEIPD, a v3 PKESK with v1 SEIPD.
      guard (seipd.version == 2) == (esk_version == 6) else {
        @error.fail(
          "api: PKESK version \{esk_version} does not align with SEIPD version \{seipd.version}",
        )
      }
      if seipd.version == 2 {
        return open_seipd_v2(seipd, session_key)
      }
      guard seipd.version == 1 else {
        @error.fail("api: unsupported SEIPD version \{seipd.version}")
      }
      let algo = match @primitives.cipher_algo_of_number(algo_id) {
        Some(a) => a
        None => @error.fail("api: unsupported session cipher \{algo_id}")
      }
      let bc = @primitives.new_block_cipher(algo, session_key.exact_view())
      return @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.exact_view())
    }
  }
  @error.fail("api: no encrypted data packet found")
}

///|
/// Decrypt an armored message with an unlocked private key.
pub fn decrypt_with_private_key(
  message : String,
  key : PrivateKey,
) -> Bytes raise {
  let armored = @armor.decode(message)
  decrypt_binary_with_private_key(@armor.ArmorBlock::data(armored), key)
}

///|
/// Candidate AEAD ciphersuites for one v6 recipient, most preferred first:
/// the preferred list as given, plus the mandatory-to-implement AES-128/OCB
/// which RFC 9580 §5.2.3.15 says is "implicitly listed at the end" when the
/// subpacket does not contain it.
fn v6_ciphersuite_candidates(recipient : PublicKey) -> Array[(Int, Int)] {
  let out : Array[(Int, Int)] = []
  for pair in recipient.preferred_aead() {
    if !out.contains(pair) {
      out.push(pair)
    }
  }
  if !out.contains((7, 2)) {
    out.push((7, 2))
  }
  out
}

///|
/// Choose the (cipher, AEAD) pair for a v6 message that *every* recipient
/// accepts, in the first recipient's preference order. RFC 9580 §13.2 says
/// an implementation "MUST NOT use a symmetric algorithm that is not in the
/// recipient's preference list", so looking at only one recipient can
/// produce a message the others cannot read. Because every candidate list
/// ends with the implicit AES-128/OCB and this library implements it, a
/// common implemented pair always exists.
fn pick_v6_ciphersuite(
  recipients : Array[PublicKey],
) -> (@primitives.CipherAlgo, @cipher.AeadMode) {
  let lists : Array[Array[(Int, Int)]] = []
  for recipient in recipients {
    lists.push(v6_ciphersuite_candidates(recipient))
  }
  for pair in lists[0] {
    let mut accepted_by_all = true
    for i in 1..<lists.length() {
      if !lists[i].contains(pair) {
        accepted_by_all = false
      }
    }
    if !accepted_by_all {
      continue
    }
    let (cipher, aead) = pair
    match
      (
        @primitives.cipher_algo_of_number(cipher),
        @cipher.aead_mode_of_number(aead),
      ) {
      (Some(c), Some(m)) => return (c, m)
      _ => ()
    }
  }
  (@primitives.Aes128, @cipher.Ocb)
}
