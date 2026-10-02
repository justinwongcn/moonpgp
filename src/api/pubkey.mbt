///|
/// Build a PKESK for one recipient over the session key, choosing the
/// algorithm by the recipient's encryption-capable key packet.
fn create_pkesk(
  enc_key : @packet.PublicKeyPacket,
  session_key : BytesView,
  sym_algo : @primitives.CipherAlgo,
) -> @packet.PkeskPacket raise {
  match enc_key.algo() {
    @packet.Ecdh => {
      let (eph, wrapped) = ecdh_wrap_session_key(enc_key, session_key, sym_algo)
      {
        key_id: enc_key.key_id(),
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
      let mpi = rsa.pkcs1_v15_encrypt(payload.view())
      {
        key_id: enc_key.key_id(),
        pub_algo: a,
        encrypted: mpi,
        ecdh_ephemeral: Bytes::new(0),
      }
    }
    _ =>
      raise @error.PgpError::PgpError(
        msg="api: recipient key algorithm cannot encrypt",
      )
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
    @packet.Ecdh => ecdh_unwrap_session_key(pkesk, sk)
    a if a.is_rsa() => {
      let key = rsa_unwrap_session_key(pkesk, sk)
      (@primitives.Aes256.number(), key)
    }
    _ =>
      raise @error.PgpError::PgpError(
        msg="api: unsupported PKESK algorithm \{pkesk.pub_algo().number()}",
      )
  }
}

///|
/// Encrypt plaintext to one or more recipients' public keys. Each
/// recipient gets its own fresh PKESK encoding of the session key
/// (RFC 9580 §5.1.3 requires re-encoding per key). Result: armored PGP
/// MESSAGE of PKESK(s) + SEIPD v1.
pub fn encrypt_to_recipients(
  plaintext : BytesView,
  recipients : Array[PublicKey],
  file_name? : String,
) -> String raise {
  guard not(recipients.is_empty()) else {
    raise @error.PgpError::PgpError(msg="api: no recipients")
  }
  let session_key = @primitives.random_bytes(SESSION_KEY_SIZE)
  let w = @packet.Writer::new()
  for recipient in recipients {
    let enc_key = match recipient.encryption_key() {
      Some(k) => k
      None =>
        raise @error.PgpError::PgpError(msg="api: recipient key cannot encrypt")
    }
    let pkesk = create_pkesk(enc_key, session_key.view(), @primitives.Aes256)
    let body = pkesk.to_body()
    w.bytes(@packet.serialize_packet(@packet.Pkesk, body.view()).view())
  }
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().view(),
  )
  let bc = @primitives.new_block_cipher(@primitives.Aes256, session_key.view())
  let seipd_ct = @cipher.seipd_v1_encrypt(bc, literal_wire.view())
  let seipd : @packet.SeipdPacket = { version: 1, ciphertext: seipd_ct, }
  w.bytes(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().view()).view(),
  )
  @armor.Message.encode(w.to_bytes().view())
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
  // Collect candidate decryption keys: primary + subkey.
  let candidates : Array[@packet.SecretKeyPacket] = [key.primary]
  match key.encryption_subkey {
    Some(sk) => candidates.push(sk)
    None => ()
  }
  let mut session : (Int, Bytes)? = None
  for p in packets {
    if p.tag() == @packet.Pkesk {
      let pkesk = @packet.PkeskPacket::parse(p.body().view())
      for sk in candidates {
        let my_id = match (try? sk.public.key_id()) {
          Ok(id) => Some(id)
          Err(_) => None
        }
        match my_id {
          Some(id) =>
            if id.equal(pkesk.key_id()) {
              session = Some(unwrap_pkesk(pkesk, sk))
              break
            }
          None => ()
        }
      }
      if session is Some(_) {
        break
      }
    }
  }
  match session {
    Some((algo, sk)) => unwrap_seipd_with_session_key(packets, algo, sk)
    None =>
      raise @error.PgpError::PgpError(
        msg="api: message is not encrypted to this key",
      )
  }
}

///|
fn rsa_unwrap_session_key(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> Bytes raise {
  let rsa = rsa_secret_parts(sk)
  let k = rsa.public.octet_length()
  guard pkesk.encrypted().length() <= k else {
    raise @error.PgpError::PgpError(msg="api: PKESK size mismatch")
  }
  // The wire MPI may have lost a leading zero octet; os2ip restores the
  // integer value either way.
  let padded = @primitives.pad_left(pkesk.encrypted().view(), k)
  let payload = rsa.pkcs1_v15_decrypt(padded.view())
  guard payload.length() >= 3 + 16 else {
    raise @error.PgpError::PgpError(msg="api: session key payload too short")
  }
  let algo = payload[0].to_int()
  guard @primitives.cipher_algo_of_number(algo) is Some(_) else {
    raise @error.PgpError::PgpError(
      msg="api: unexpected session key cipher \{algo}",
    )
  }
  let key_len = payload.length() - 3
  let key = payload[1:1 + key_len]
  let want = (payload[payload.length() - 2].to_int() << 8) |
    payload[payload.length() - 1].to_int()
  guard @packet.session_key_checksum(key.view()) == want else {
    raise @error.PgpError::PgpError(msg="api: session key checksum mismatch")
  }
  key.to_owned()
}

///|
fn unwrap_seipd_with_session_key(
  packets : Array[@packet.RawPacket],
  algo_id : Int,
  session_key : Bytes,
) -> Bytes raise {
  for p in packets {
    if p.tag() == @packet.Seipd {
      let seipd = @packet.SeipdPacket::parse(p.body().view())
      guard seipd.version == 1 else {
        raise @error.PgpError::PgpError(
          msg="api: unsupported SEIPD version \{seipd.version}",
        )
      }
      let algo = match @primitives.cipher_algo_of_number(algo_id) {
        Some(a) => a
        None =>
          raise @error.PgpError::PgpError(
            msg="api: unsupported session cipher \{algo_id}",
          )
      }
      let bc = @primitives.new_block_cipher(algo, session_key.view())
      let inner = @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.view())
      return extract_literal(inner)
    }
  }
  raise @error.PgpError::PgpError(msg="api: no encrypted data packet found")
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
