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
      // session-key checksum (the v2 SEIPD names the cipher). The X25519
      // PKESK shape is v6-only: it must precede a v2 SEIPD, so a v4
      // recipient with an X25519 key cannot be encrypted to here.
      guard enc_key.version() >= 6 else {
        @error.fail(
          "api: X25519 encryption requires a v6 key (v4 X25519 keys are import/verify only)",
        )
      }
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
) -> (Int32, Bytes) raise {
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
  compress? : @compress.CompressedAlgo,
) -> String raise {
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  seal_to_recipients(
    maybe_compress_inner(literal_wire, compress?).exact_view(),
    recipients,
  )
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
  // Lifecycle gate (M1): refuse to spend a session key on a recipient
  // whose key is revoked or no longer encryption-capable. The clock is
  // real on native; on the non-native targets it reads 0, which disables
  // the time-dependent part of the checks (documented degradation).
  let now = @primitives.unix_now()
  for recipient in recipients {
    guard !recipient.is_revoked(now) else {
      @error.fail("api: recipient key is revoked")
    }
    guard recipient.can_encrypt(now) else {
      @error.fail("api: recipient key is expired or cannot encrypt")
    }
    let enc_key = match recipient.encryption_packet_at(now) {
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
const SEIPD_V2_CHUNK_OCTET : Int32 = 14

///|
/// Seal a v2 SEIPD packet (RFC 9580 §5.13.2): fresh 32-octet salt, HKDF
/// message key and nonce, chunked AEAD.
fn seal_seipd_v2(
  algo : @primitives.CipherAlgo,
  mode : @cipher.AeadMode,
  chunk_octet : Int32,
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
fn checksum_bytes(sum : Int32) -> Bytes {
  Bytes::from_array([(sum >> 8).to_byte(), sum.to_byte()])
}

///|
/// Decrypt a binary message with an unlocked private key. Matches PKESKs
/// against the key's ids (RSA or ECDH), recovers the session key, checks
/// the session-key checksum, and unwraps the SEIPD payload.
pub fn decrypt_binary_with_private_key(
  data : BytesView,
  key : PrivateKey,
  max_decompressed~ : Int32 = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> Bytes raise {
  let packets = @packet.parse_packets(data)
  let inner = match decrypt_inner_with_key(packets, key) {
    Some(b) => b
    None => @error.fail("api: message is not encrypted to this key")
  }
  extract_literal(inner, max_decompressed)
}

///|
/// Does this PKESK address the given (unlocked) secret key? v6 by
/// fingerprint, v3 by key id. Shared by the decrypt pipeline and the
/// session-key recovery flow.
fn pkesk_addresses(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> Bool {
  if pkesk.version() == 6 {
    // §5.1.2: a v6 PKESK identifies the recipient by fingerprint.
    let fp = sk.public.fingerprint() catch { _ => Bytes::new(0) }
    pkesk.fingerprint().length() > 0 && fp.equal(pkesk.fingerprint())
  } else {
    let id = sk.public.key_id() catch { _ => Bytes::new(0) }
    id.equal(pkesk.key_id())
  }
}

///|
/// True for a v3 PKESK whose key id is all zero — a hidden recipient
/// (S13): it matches no key by id, so every candidate secret key must be
/// tried, like go-crypto's KeyDecryption with a zero key id.
fn pkesk_is_anonymous(pkesk : @packet.PkeskPacket) -> Bool {
  if pkesk.version() == 6 {
    return false
  }
  let id = pkesk.key_id()
  let mut all_zero = id.length() == 8
  for b in id {
    if b != b'\x00' {
      all_zero = false
    }
  }
  all_zero
}

///|
/// Unwrap `pkesk` with `sk` and open the SEIPD container in `packets`.
/// Shared by both PKESK-consuming flows; raises on any failure.
fn decrypt_with_pkesk(
  packets : Array[@packet.RawPacket],
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> Bytes raise {
  let (algo, session) = unwrap_pkesk(pkesk, sk)
  unwrap_seipd_inner(packets, algo, session, pkesk.version())
}

///|
/// Match a PKESK in `packets` against `key` — v6 by fingerprint, v3 by key
/// id, over the primary key and the encryption subkey — recover the session
/// key and return the raw inner packet stream of the SEIPD container. `None`
/// means no PKESK belongs to this key; a matched packet that cannot be
/// decrypted raises. A v3 PKESK with an all-zero key id (hidden recipient)
/// is tried against every candidate: a candidate that fails to unwrap is
/// simply not the recipient. Shared by `decrypt_binary_with_private_key` and
/// the sign/decrypt pipeline in `sign.mbt`, so both accept the same messages.
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
      if pkesk_is_anonymous(pkesk) {
        for sk in candidates {
          let inner : Bytes? = Some(decrypt_with_pkesk(packets, pkesk, sk)) catch {
            _ => None
          }
          if inner is Some(b) {
            return Some(b)
          }
        }
        continue
      }
      for sk in candidates {
        if pkesk_addresses(pkesk, sk) {
          return Some(decrypt_with_pkesk(packets, pkesk, sk))
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
///
/// Bleichenbacher countermeasure (S04): any failure inside the checked
/// path — modulus mismatch, PKCS#1 framing, payload shape, checksum —
/// yields a RANDOM session key instead of an error, mirroring Go's
/// `rsa.DecryptPKCS1v15SessionKey` as used by go-crypto. The wrong key
/// then fails uniformly inside the SEIPD integrity check, so an attacker
/// with a decryption oracle cannot distinguish where unwrapping went
/// wrong.
fn rsa_unwrap_session_key(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> (Int32, Bytes) raise {
  match rsa_unwrap_checked(pkesk, sk) {
    Some(pair) => pair
    None => {
      // A random AES-256 key of the correct length: the following SEIPD
      // v1 CFB/MDC (or v2 AEAD) open fails identically to any other
      // wrong-session-key decryption.
      let algo = @primitives.Aes256
      (algo.number(), @primitives.random_bytes(algo.key_size()))
    }
  }
}

///|
/// The real RSA PKESK unwrap; `None` marks every rejection that must be
/// masked by the random-key fallback above.
fn rsa_unwrap_checked(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> (Int32, Bytes)? raise {
  let rsa = rsa_secret_parts(sk)
  let k = rsa.public.octet_length()
  guard pkesk.encrypted().length() <= k else { return None }
  // The wire MPI may have lost a leading zero octet; os2ip restores the
  // integer value either way.
  let padded = @primitives.pad_left(pkesk.encrypted().exact_view(), k)
  let payload = rsa.pkcs1_v15_decrypt(padded.exact_view()) catch {
    _ => return None
  }
  guard payload.length() >= 3 + 16 else { return None }
  let algo = payload[0].to_int()
  guard @primitives.cipher_algo_of_number(algo) is Some(_) else { return None }
  let key_len = payload.length() - 3
  let key = payload[1:1 + key_len]
  let want = (payload[payload.length() - 2].to_int() << 8) |
    payload[payload.length() - 1].to_int()
  guard @packet.session_key_checksum(key.exact_view()) == want else {
    return None
  }
  Some((algo, key.to_owned()))
}

///|
/// Decrypt the SEIPD container in `packets` and return its raw inner packet
/// stream. A v2 container names its own cipher, so the PKESK/SKESK
/// algorithm id is unused there; a v1 container takes it from the ESK
/// packet because SEIPD v1 carries no cipher of its own.
fn unwrap_seipd_inner(
  packets : Array[@packet.RawPacket],
  algo_id : Int32,
  session_key : Bytes,
  esk_version : Int32,
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
  max_decompressed~ : Int32 = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> Bytes raise {
  let armored = @armor.decode(message)
  decrypt_binary_with_private_key(
    @armor.ArmorBlock::data(armored),
    key,
    max_decompressed~,
  )
}

///|
/// Candidate AEAD ciphersuites for one v6 recipient, most preferred first:
/// the preferred list as given, plus the mandatory-to-implement AES-128/OCB
/// which RFC 9580 §5.2.3.15 says is "implicitly listed at the end" when the
/// subpacket does not contain it.
fn v6_ciphersuite_candidates(recipient : PublicKey) -> Array[(Int32, Int32)] {
  let out : Array[(Int32, Int32)] = []
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
  let lists : Array[Array[(Int32, Int32)]] = []
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
