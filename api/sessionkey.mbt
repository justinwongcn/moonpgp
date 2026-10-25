///|
/// Session-key entry points (M3), mirroring gopenpgp's `crypto.SessionKey`
/// and its `EncryptSessionKey`/`DecryptSessionKey` flows. Session keys
/// normally stay internal to `encrypt_to_recipients`/`encrypt_with_password`;
/// these exist for the out-of-band uses — sealing a message to a session
/// key the caller already holds (no ESK packets on the wire) and
/// recovering a session key from a message so it can be re-wrapped or
/// stored elsewhere.

///|
/// A symmetric session key with the cipher that interprets it. `key`
/// must be `algo.key_size()` octets — `SessionKey::new` enforces it;
/// direct struct construction bypasses the check and fails at first use
/// inside the block-cipher constructor.
pub(all) struct SessionKey {
  key : Bytes
  algo : @primitives.CipherAlgo
} derive(Debug)

///|
pub extend SessionKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
/// Build a session key, validating the key length against the cipher.
pub fn SessionKey::new(
  key : BytesView,
  algo : @primitives.CipherAlgo,
) -> SessionKey raise {
  guard key.length() == algo.key_size() else {
    @error.fail(
      "api: session key length \{key.length()} does not match the cipher's \{algo.key_size()}",
    )
  }
  SessionKey::{ key: key.to_owned(), algo, }
}

///|
/// The raw session-key octets.
pub fn SessionKey::key(self : SessionKey) -> Bytes {
  self.key
}

///|
/// The cipher this session key belongs to.
pub fn SessionKey::algo(self : SessionKey) -> @primitives.CipherAlgo {
  self.algo
}

///|
/// Generate a fresh random session key (platform entropy; AES-256 unless
/// another cipher is requested).
pub fn generate_session_key(
  algo~ : @primitives.CipherAlgo = @primitives.Aes256,
) -> SessionKey raise {
  SessionKey::new(@primitives.random_bytes(algo.key_size()), algo)
}

///|
/// Encrypt plaintext under a caller-held session key: a bare SEIPD v1
/// container with no PKESK/SKESK — only whoever holds `sk` out of band
/// can read it (the gopenpgp "raw session key" backend).
pub fn encrypt_to_session_key(
  plaintext : BytesView,
  sk : SessionKey,
  file_name? : String,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let inner = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let inner = maybe_compress_inner(inner, compress?)
  let bc = @primitives.new_block_cipher(sk.algo, sk.key.exact_view())
  let ct = @cipher.seipd_v1_encrypt(bc, inner.exact_view())
  let seipd : @packet.SeipdPacket = {
    version: 1,
    cipher_algo: 0,
    aead_algo: 0,
    chunk_octet: 0,
    salt: Bytes::new(0),
    ciphertext: ct,
  }
  @armor.Message.encode(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().exact_view()).exact_view(),
  )
}

///|
/// Decrypt a message with a caller-held session key. The message may be
/// a bare SEIPD container (from `encrypt_to_session_key`) or a normal
/// PKESK/SKESK-protected message whose session key the caller knows.
pub fn decrypt_to_session_key(message : String, sk : SessionKey) -> Bytes raise {
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(block).exact_view(),
  )
  let bc = @primitives.new_block_cipher(sk.algo, sk.key.exact_view())
  for p in packets {
    if p.tag() == @packet.Seipd {
      let seipd = @packet.SeipdPacket::parse(p.body().exact_view())
      if seipd.version == 1 {
        return extract_literal(
          @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.exact_view()),
          DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
      }
      return extract_literal(
        open_seipd_v2(seipd, sk.key),
        DEFAULT_MAX_DECOMPRESSED_BYTES,
      )
    }
  }
  @error.fail("api: no SEIPD packet found")
}

///|
/// Recover the session key of a password-encrypted message (the
/// gopenpgp `RetrieveSessionKey` flow): unwrap the SKESK without
/// touching the payload.
pub fn recover_session_key_with_password(
  message : String,
  passphrase : String,
  argon2_max_memory_kib~ : Int32 = @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
) -> SessionKey raise {
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(block).exact_view(),
  )
  let (algo, key, _) = unwrap_skesk(packets, passphrase, argon2_max_memory_kib)
  SessionKey::new(key, algo)
}

///|
/// Recover the session key of a message encrypted to `key`'s public key:
/// unwrap the matching PKESK without decrypting the payload. The
/// algorithm id comes from the PKESK payload for the v4 shape and from
/// the SEIPD v2 header for v6.
pub fn recover_session_key_with_key(
  message : String,
  key : PrivateKey,
) -> SessionKey raise {
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(block).exact_view(),
  )
  let candidates : Array[@packet.SecretKeyPacket] = [key.primary]
  for c in key.subkeys {
    candidates.push(c.secret)
  }
  for p in packets {
    if p.tag() == @packet.Pkesk {
      let pkesk = @packet.PkeskPacket::parse(p.body().exact_view())
      // Hidden recipient (S13): an all-zero v3 key id matches no key by
      // id, so every candidate is tried; a failing candidate is just not
      // the recipient.
      if pkesk_is_anonymous(pkesk) {
        for sk in candidates {
          let recovered : SessionKey? = Some(
            recover_pkesk_session(packets, pkesk, sk),
          ) catch {
            _ => None
          }
          if recovered is Some(s) {
            return s
          }
        }
        continue
      }
      for sk in candidates {
        if pkesk_addresses(pkesk, sk) {
          return recover_pkesk_session(packets, pkesk, sk)
        }
      }
    }
  }
  @error.fail("api: message is not encrypted to this key")
}

///|
/// Unwrap one PKESK into a session key: the algorithm id comes from the
/// PKESK payload for the v3 shape and from the SEIPD v2 header for v6.
fn recover_pkesk_session(
  packets : Array[@packet.RawPacket],
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> SessionKey raise {
  let (algo_id, session) = unwrap_pkesk(pkesk, sk)
  if pkesk.version() == 6 {
    // A v6 PKESK carries no cipher octet; the v2 SEIPD names it.
    for q in packets {
      if q.tag() == @packet.Seipd {
        let seipd = @packet.SeipdPacket::parse(q.body().exact_view())
        guard seipd.version == 2 else {
          @error.fail(
            "api: v6 PKESK must precede a v2 SEIPD (RFC 9580 §10.3.2.1)",
          )
        }
        let algo = match @primitives.cipher_algo_of_number(seipd.cipher_algo) {
          Some(a) => a
          None =>
            @error.fail("api: unsupported session cipher \{seipd.cipher_algo}")
        }
        return SessionKey::new(session, algo)
      }
    }
    @error.fail("api: no SEIPD packet found")
  }
  let algo = match @primitives.cipher_algo_of_number(algo_id) {
    Some(a) => a
    None => @error.fail("api: unsupported session cipher \{algo_id}")
  }
  SessionKey::new(session, algo)
}
