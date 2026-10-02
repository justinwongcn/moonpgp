///|
/// Canonicalize text for text signatures (type 0x01): line endings become
/// CRLF (RFC 9580 §5.2.4).
pub fn canonicalize_text(data : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let mut prev_cr = false
  for b in data {
    if b == b'\n' {
      if not(prev_cr) {
        out.push(b'\r')
      }
      out.push(b'\n')
      prev_cr = false
    } else {
      if b == b'\r' {
        prev_cr = true
      } else {
        prev_cr = false
      }
      out.push(b)
    }
  }
  Bytes::from_array(out)
}

///|
/// Document bytes hashed for a signature over `data` with sig type 0x00
/// (binary) or 0x01 (canonical text).
fn document_hash(
  sig : @packet.SignaturePacket,
  data : BytesView,
  sig_type : @packet.SigType,
) -> Bytes raise {
  let content : Bytes = match sig_type {
    @packet.CanonicalTextDocument => canonicalize_text(data)
    _ => data.to_owned()
  }
  let w = @packet.Writer::new()
  w.bytes(content.view())
  w.bytes(sig.hash_prefix().view())
  w.bytes(@packet.signature_trailer(sig.hash_prefix().length()).view())
  match @primitives.hash_id_of_number(sig.hash_algo()) {
    Some(h) => h.digest(w.to_bytes().view())
    None => raise @error.PgpError::PgpError(msg="api: unknown hash algorithm")
  }
}

///|
/// Build a v4 document signature with the given type and default hash.
fn make_document_signature(
  key : PrivateKey,
  data : BytesView,
  sig_type : @packet.SigType,
) -> @packet.SignaturePacket raise {
  make_document_signature_with(key, data, sig_type, @primitives.Sha256)
}

///|
/// Build a v4 text signature with an explicit hash algorithm.
fn make_text_signature(
  key : PrivateKey,
  data : BytesView,
  hash : @primitives.HashId,
) -> @packet.SignaturePacket raise {
  make_document_signature_with(key, data, @packet.CanonicalTextDocument, hash)
}

///|
fn make_document_signature_with(
  key : PrivateKey,
  data : BytesView,
  sig_type : @packet.SigType,
  hash : @primitives.HashId,
) -> @packet.SignaturePacket raise {
  let now = @primitives.unix_now().to_int()
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x02),
  ]
  let issuer : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
      body: match (try? key.primary.public.key_id()) {
        Ok(id) => id
        Err(_) => Bytes::new(0)
      },
    },
  ]
  let sig : @packet.SignaturePacket = {
    sig_type,
    pub_algo: key.primary.public.algo(),
    hash_algo: hash.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: issuer,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    sig_params: [],
  }
  let digest = document_hash(sig, data, sig_type)
  finish_signature(sig, key.primary, hash, digest.view())
}

///|
/// Create a detached ASCII-armored signature over `data`.
pub fn sign_detached(
  data : BytesView,
  key : PrivateKey,
  text_mode? : Bool,
) -> String raise {
  let sig_type : @packet.SigType = if text_mode.unwrap_or(false) {
    @packet.CanonicalTextDocument
  } else {
    @packet.BinaryDocument
  }
  let sig = make_document_signature(key, data, sig_type)
  @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().view()).view(),
  )
}

///|
/// Verification outcome, mirroring gopenpgp's status codes
/// (OK / NOT_SIGNED / NO_VERIFIER / FAILED).
pub(all) enum VerifyStatus {
  /// Signature verified against the given key.
  Ok
  /// The message carried no signature at all.
  NotSigned
  /// The signature belongs to a key we cannot verify with.
  NoVerifier
  /// A matching key was present but verification failed.
  Failed
} derive(Eq, Debug)

///|
/// Verify a detached armored signature over `data` using `verifier`.
pub fn verify_detached(
  data : BytesView,
  armored_signature : String,
  verifier : PublicKey,
) -> VerifyStatus raise {
  let block = @armor.decode(armored_signature)
  guard block.armor_type() == @armor.Signature else {
    raise @error.PgpError::PgpError(msg="api: not a signature armor block")
  }
  // The armor payload is a packet sequence; find the signature packet.
  let packets = @packet.parse_packets(block.data().view())
  let mut sig : @packet.SignaturePacket? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().view()))
      break
    }
  }
  match sig {
    Some(s) => verify_signature_packet(s, data, verifier)
    None =>
      raise @error.PgpError::PgpError(
        msg="api: no signature packet in armor block",
      )
  }
}

///|
/// Verify a signature packet over document data with a transferable key.
fn verify_signature_packet(
  sig : @packet.SignaturePacket,
  data : BytesView,
  verifier : PublicKey,
) -> VerifyStatus raise {
  // Which key of the transferable key issued this signature?
  let issuer = sig.issuer_key_id()
  let primary_id = verifier.primary.key_id()
  let sub_id : Bytes? = match verifier.encryption_subkey {
    Some(sub) =>
      match (try? sub.key_id()) {
        Ok(id) => Some(id)
        Err(_) => None
      }
    None => None
  }
  let signer : @packet.PublicKeyPacket? = match issuer {
    Some(id) =>
      if primary_id.equal(id) {
        Some(verifier.primary)
      } else if sub_id is Some(_) && sub_id.unwrap().equal(id) {
        verifier.encryption_subkey
      } else {
        None
      }
    None => Some(verifier.primary)
  }
  match signer {
    None => NoVerifier
    Some(signer_pk) => {
      let digest = document_hash(sig, data, sig.sig_type())
      let hash_id = match @primitives.hash_id_of_number(sig.hash_algo()) {
        Some(h) => h
        None => return Failed
      }
      match
        (try? verify_sig_material(
          signer_pk,
          hash_id,
          digest.view(),
          sig.sig_params(),
        )) {
        Ok(true) => Ok
        _ => Failed
      }
    }
  }
}

///|
/// Create an inline-signed, armored message: One-Pass-Signature ||
/// Literal || Signature.
pub fn sign_inline(
  data : BytesView,
  key : PrivateKey,
  text_mode? : Bool,
) -> String raise {
  let sig_type : @packet.SigType = if text_mode.unwrap_or(false) {
    @packet.CanonicalTextDocument
  } else {
    @packet.BinaryDocument
  }
  let sig = make_document_signature(key, data, sig_type)
  let literal = @packet.LiteralPacket::binary(data, file_name="message.txt")
  let ops : @packet.OnePassSigPacket = {
    sig_type,
    hash_algo: @primitives.Sha256.number(),
    pub_algo: key.primary.public.algo(),
    key_id: key.primary.public.key_id(),
    nested: false,
  }
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.OnePassSig, ops.to_body().view()).view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Literal, literal.to_body().view()).view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().view()).view(),
  )
  @armor.Message.encode(w.to_bytes().view())
}

///|
/// Verify an inline-signed armored message; returns the literal data and
/// the verification status against `verifier`.
pub fn verify_inline(
  message : String,
  verifier : PublicKey,
) -> (Bytes, VerifyStatus) raise {
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(block.data().view())
  // Locate literal (or compressed) data and the trailing signature.
  let mut data : Bytes? = None
  let mut sig : @packet.SignaturePacket? = None
  let n = packets.length()
  let mut i = 0
  while i < n {
    let p = packets[i]
    if p.tag() == @packet.OnePassSig {
      // skip
    } else if p.tag() == @packet.Literal {
      data = Some(@packet.LiteralPacket::parse(p.body().view()).data())
    } else if p.tag() == @packet.Compressed {
      let comp = @packet.CompressedPacket::parse(p.body().view())
      let inner : Bytes = match comp.algo {
        0 => comp.data
        1 => @compress.zip_decompress(comp.data.view())
        2 => @compress.zlib_decompress(comp.data.view())
        _ =>
          raise @error.PgpError::PgpError(
            msg="api: unsupported compression algorithm \{comp.algo}",
          )
      }
      // The compressed stream may be [Literal] or [OPS, Literal, Sig]
      // (gpg -es); find the literal and the signature anywhere in it.
      for q in @packet.parse_packets(inner.view()) {
        if q.tag() == @packet.Literal {
          data = Some(@packet.LiteralPacket::parse(q.body().view()).data())
        } else if q.tag() == @packet.Signature {
          sig = Some(@packet.SignaturePacket::parse(q.body().view()))
        }
      }
    } else if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().view()))
    }
    i = i + 1
  }
  match (data, sig) {
    (Some(d), Some(s)) => {
      let status = verify_signature_packet(s, d.view(), verifier)
      (d, status)
    }
    (Some(d), None) => (d, NotSigned)
    _ => raise @error.PgpError::PgpError(msg="api: message has no data packet")
  }
}

///|
/// Sign and encrypt in one step (inline signature inside SEIPD).
pub fn sign_and_encrypt(
  data : BytesView,
  signer : PrivateKey,
  recipients : Array[PublicKey],
  text_mode? : Bool,
) -> String raise {
  let sig_type : @packet.SigType = if text_mode.unwrap_or(false) {
    @packet.CanonicalTextDocument
  } else {
    @packet.BinaryDocument
  }
  let sig = make_document_signature(signer, data, sig_type)
  let literal = @packet.LiteralPacket::binary(data, file_name="message.txt")
  let ops : @packet.OnePassSigPacket = {
    sig_type,
    hash_algo: @primitives.Sha256.number(),
    pub_algo: signer.primary.public.algo(),
    key_id: signer.primary.public.key_id(),
    nested: false,
  }
  let inner = @packet.Writer::new()
  inner.bytes(
    @packet.serialize_packet(@packet.OnePassSig, ops.to_body().view()).view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Literal, literal.to_body().view()).view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().view()).view(),
  )
  encrypt_stream_to_recipients(inner.to_bytes().view(), recipients)
}

///|
/// Encrypt a pre-serialized inner packet stream to recipients.
fn encrypt_stream_to_recipients(
  inner : BytesView,
  recipients : Array[PublicKey],
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
  let bc = @primitives.new_block_cipher(@primitives.Aes256, session_key.view())
  let seipd_ct = @cipher.seipd_v1_encrypt(bc, inner)
  let seipd : @packet.SeipdPacket = { version: 1, ciphertext: seipd_ct, }
  w.bytes(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().view()).view(),
  )
  @armor.Message.encode(w.to_bytes().view())
}

///|
/// Decrypt an armored message (password OR private keys) and verify an
/// inline signature against `verifier`. Returns (data, status).
pub fn decrypt_and_verify(
  message : String,
  decryption_keys : Array[PrivateKey],
  verifier : PublicKey?,
) -> (Bytes, VerifyStatus) raise {
  // Try private-key decryption first, then fall back to no-password
  // path only when no keys given? Keep explicit: caller decides.
  let block = @armor.decode(message)
  let data_bytes = @armor.ArmorBlock::data(block)
  // Decrypt
  let packets = @packet.parse_packets(data_bytes.view())
  let mut session : (Int, Bytes)? = None
  for key in decryption_keys {
    let mut found = false
    for p in packets {
      if p.tag() == @packet.Pkesk {
        let pkesk = @packet.PkeskPacket::parse(p.body().view())
        let candidates = [key.primary]
        match key.encryption_subkey {
          Some(sk) => candidates.push(sk)
          None => ()
        }
        for sk in candidates {
          let my_id = match (try? sk.public.key_id()) {
            Ok(id) => Some(id)
            Err(_) => None
          }
          match my_id {
            Some(id) =>
              if id.equal(pkesk.key_id()) {
                session = Some(unwrap_pkesk(pkesk, sk))
                found = true
                break
              }
            None => ()
          }
        }
        if found {
          break
        }
      }
    }
    if found {
      break
    }
  }
  // Decrypt the SEIPD and keep the raw inner packet stream (it may carry
  // a one-pass signature around the literal data).
  let inner : Bytes = match session {
    Some((algo_id, sk)) => {
      let mut found : Bytes? = None
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
          let bc = @primitives.new_block_cipher(algo, sk.view())
          found = Some(@cipher.seipd_v1_decrypt(bc, seipd.ciphertext.view()))
          break
        }
      }
      match found {
        Some(b) => b
        None =>
          raise @error.PgpError::PgpError(
            msg="api: no encrypted data packet found",
          )
      }
    }
    None =>
      raise @error.PgpError::PgpError(msg="api: no matching decryption key")
  }
  // Walk inner packets: OPS? literal | compressed; trailing sig.
  let inner_packets = @packet.parse_packets(inner.view())
  let mut data : Bytes? = None
  let mut sig : @packet.SignaturePacket? = None
  for p in inner_packets {
    if p.tag() == @packet.Literal {
      data = Some(@packet.LiteralPacket::parse(p.body().view()).data())
    } else if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().view()))
    } else if p.tag() == @packet.Compressed {
      let comp = @packet.CompressedPacket::parse(p.body().view())
      let payload : Bytes = match comp.algo {
        0 => comp.data
        1 => @compress.zip_decompress(comp.data.view())
        2 => @compress.zlib_decompress(comp.data.view())
        _ => raise @error.PgpError::PgpError(msg="api: unsupported compression")
      }
      // The compressed stream may be [Literal] or [OPS, Literal, Sig]
      // (gpg -es); find the literal and the signature anywhere in it.
      for q in @packet.parse_packets(payload.view()) {
        if q.tag() == @packet.Literal {
          data = Some(@packet.LiteralPacket::parse(q.body().view()).data())
        } else if q.tag() == @packet.Signature {
          sig = Some(@packet.SignaturePacket::parse(q.body().view()))
        }
      }
    }
  }
  match (data, sig) {
    (Some(d), Some(s)) => {
      let status : VerifyStatus = match verifier {
        Some(v) => verify_signature_packet(s, d.view(), v)
        None => NoVerifier
      }
      (d, status)
    }
    (Some(d), None) => (d, NotSigned)
    _ => raise @error.PgpError::PgpError(msg="api: message has no data packet")
  }
}
