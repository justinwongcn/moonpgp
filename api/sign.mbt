///|
/// Canonicalize text for text signatures (type 0x01): line endings become
/// CRLF (RFC 9580 §5.2.4).
fn canonicalize_text(data : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let mut prev_cr = false
  for b in data {
    if b == b'\n' {
      if !prev_cr {
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
/// (binary) or 0x01 (canonical text). Version 6 prepends the salt to the
/// hash input (RFC 9580 §5.2.4) and uses a 4-octet trailer length.
fn document_hash(
  sig : @packet.SignaturePacket,
  data : BytesView,
  sig_type : @packet.SigType,
) -> Bytes raise {
  let content : Bytes = match sig_type {
    @packet.CanonicalTextDocument => canonicalize_text(data)
    _ => data.to_owned()
  }
  finish_signed_digest(sig, content.exact_view())
}

///|
/// Hash input assembly shared by document and key signatures: the salt
/// (v6 only, before everything else), the framed data, the hash prefix
/// and the version-appropriate trailer.
fn finish_signed_digest(
  sig : @packet.SignaturePacket,
  data : BytesView,
) -> Bytes raise {
  let w = @packet.Writer::new()
  w.bytes(sig.salt().exact_view())
  w.bytes(data)
  w.bytes(sig.hash_prefix().exact_view())
  w.bytes(
    @packet.signature_trailer(sig.version(), sig.hash_prefix().length()).exact_view(),
  )
  match @primitives.hash_id_of_number(sig.hash_algo()) {
    Some(h) => h.digest(w.to_bytes().exact_view())
    None => @error.fail("api: unknown hash algorithm")
  }
}

///|
/// Issuer Fingerprint subpacket body: version octet || fingerprint
/// (RFC 9580 §5.2.3.33). This is how v6 signatures identify their key —
/// the Issuer Key ID subpacket MUST NOT be used for keys newer than v4.
fn issuer_fingerprint_subpacket(
  pub_packet : @packet.PublicKeyPacket,
) -> @packet.SigSubpacket raise {
  let fp = pub_packet.fingerprint()
  let w = @packet.Writer::new()
  w.u8(pub_packet.version())
  w.bytes(fp.exact_view())
  {
    critical: false,
    sub_type: @packet.SIGSUB_ISSUER_FINGERPRINT,
    body: w.to_bytes(),
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
  let v6 = key.primary.public.version() >= 6
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x02),
  ]
  if v6 {
    hashed.push(issuer_fingerprint_subpacket(key.primary.public))
  }
  let unhashed : Array[@packet.SigSubpacket] = if v6 {
    // §5.2.3.12: no Issuer Key ID subpacket on v6 signatures; the
    // fingerprint subpacket above carries the issuer.
    []
  } else {
    [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        // No catch: a key whose id cannot be computed must fail the signing
        // loudly, not emit a signature with an empty issuer (F15).
        body: key.primary.public.key_id(),
      },
    ]
  }
  let salt : Bytes = if v6 {
    @primitives.random_bytes(@packet.salt_size_of_hash(hash.number()))
  } else {
    Bytes::new(0)
  }
  let sig : @packet.SignaturePacket = {
    version: if v6 {
      6
    } else {
      4
    },
    sig_type,
    pub_algo: key.primary.public.algo(),
    hash_algo: hash.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt,
    sig_params: [],
  }
  let digest = document_hash(sig, data, sig_type)
  finish_signature(sig, key.primary, hash, digest.exact_view())
}

///|
/// Signature type from the optional `text_mode` flag.
fn sig_type_of(text_mode : Bool?) -> @packet.SigType {
  if text_mode.unwrap_or(false) {
    @packet.CanonicalTextDocument
  } else {
    @packet.BinaryDocument
  }
}

///|
/// Default ceiling on decompressed payload size (M4): a 512 MiB bound on
/// what an untrusted compressed packet may expand to. Mirrors the Argon2
/// pre-allocation cap policy; override per call with
/// `max_decompressed~`.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES : Int = 536870912

///|
/// Decompress a compressed packet payload (shared by the verification and
/// decryption walks, F16) under a hard output cap.
fn decompress_payload(
  comp : @packet.CompressedPacket,
  max_out : Int,
) -> Bytes raise {
  match comp.algo {
    0 => comp.data
    1 => @compress.zip_decompress_capped(comp.data.exact_view(), max_out)
    2 => @compress.zlib_decompress_capped(comp.data.exact_view(), max_out)
    _ => @error.fail("api: unsupported compression algorithm \{comp.algo}")
  }
}

///|
/// Optionally wrap an inner packet stream in a Compressed packet (M4).
/// Only ZIP/ZLIB have codecs here — BZip2 is decode-only and
/// `Uncompressed` means the caller passed something odd.
fn maybe_compress_inner(
  inner : BytesView,
  compress? : @compress.CompressedAlgo,
) -> Bytes raise {
  match compress {
    None => inner.to_owned()
    Some(algo) =>
      match algo {
        // Body = algorithm octet || compressed stream (RFC 9580 §5.6).
        @compress.Zip =>
          @packet.serialize_packet(
            @packet.Compressed,
            Bytes::from_array([1])
            .add(@compress.zip_compress(inner))
            .exact_view(),
          )
        @compress.Zlib =>
          @packet.serialize_packet(
            @packet.Compressed,
            Bytes::from_array([2])
            .add(@compress.zlib_compress(inner))
            .exact_view(),
          )
        _ =>
          @error.fail(
            "api: unsupported output compression algorithm (BZip2 is decode-only)",
          )
      }
  }
}

///|
/// Walk a packet stream collecting the literal data and the signature,
/// recursing into compressed packets (they carry either [Literal] or the
/// [OPS, Literal, Sig] gpg -es shape). Returns the accumulated
/// (data, sig); unknown tags (e.g. OnePassSig) are skipped.
fn collect_data_sig(
  packets : Array[@packet.RawPacket],
  data0 : Bytes?,
  sig0 : @packet.SignaturePacket?,
  max_decompressed : Int,
) -> (Bytes?, @packet.SignaturePacket?) raise {
  let mut data = data0
  let mut sig = sig0
  for p in packets {
    match p.tag() {
      @packet.Literal =>
        data = Some(@packet.LiteralPacket::parse(p.body().exact_view()).data())
      @packet.Signature =>
        sig = Some(@packet.SignaturePacket::parse(p.body().exact_view()))
      @packet.Compressed => {
        let inner = decompress_payload(
          @packet.CompressedPacket::parse(p.body().exact_view()),
          max_decompressed,
        )
        let (d2, s2) = collect_data_sig(
          @packet.parse_packets(inner.exact_view()),
          data,
          sig,
          max_decompressed,
        )
        data = d2
        sig = s2
      }
      _ => ()
    }
  }
  (data, sig)
}

///|
/// Combine the collected data/signature into the verification outcome.
fn finish_inline_verify(
  data : Bytes?,
  sig : @packet.SignaturePacket?,
  verifier : PublicKey?,
) -> (Bytes, VerifyStatus) raise {
  match (data, sig) {
    (Some(d), Some(s)) => {
      let status : VerifyStatus = match verifier {
        Some(v) => verify_signature_packet(s, d.exact_view(), v)
        None => NoVerifier
      }
      (d, status)
    }
    (Some(d), None) => (d, NotSigned)
    _ => @error.fail("api: message has no data packet")
  }
}

///|
/// Create a detached ASCII-armored signature over `data`.
pub fn sign_detached(
  data : BytesView,
  key : PrivateKey,
  text_mode? : Bool,
) -> String raise {
  let sig_type = sig_type_of(text_mode)
  let sig = make_document_signature(key, data, sig_type)
  @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
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
    @error.fail("api: not a signature armor block")
  }
  // The armor payload is a packet sequence; find the signature packet.
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut sig : @packet.SignaturePacket? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().exact_view()))
      break
    }
  }
  match sig {
    Some(s) => verify_signature_packet(s, data, verifier)
    None => @error.fail("api: no signature packet in armor block")
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
  // Lenient on purpose (F15): a subkey whose id cannot be computed merely
  // drops out of the candidate match; verification must not fail for it.
  let sub_id : Bytes? = match verifier.encryption_subkey {
    Some(sub) => Some(sub.key_id()) catch { _ => None }
    None => None
  }
  let signer : @packet.PublicKeyPacket? = match issuer {
    Some(id) =>
      if primary_id.equal(id) {
        Some(verifier.primary)
      } else if sub_id is Some(sid) && sid.equal(id) {
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
      // RFC 9580 §5.2.4: a v6 verifier MUST reject the signature when the
      // left 16 bits of the digest do not match the stored hash tag.
      if sig.version() >= 6 {
        let tag = (digest[0].to_int() << 8) | digest[1].to_int()
        if tag != sig.fast_hash() {
          return Failed
        }
      }
      let hash_id = match @primitives.hash_id_of_number(sig.hash_algo()) {
        Some(h) => h
        None => return Failed
      }
      let verified = verify_sig_material(
        signer_pk,
        hash_id,
        digest.exact_view(),
        sig.sig_params(),
      ) catch {
        _ => false
      }
      if verified {
        Ok
      } else {
        Failed
      }
    }
  }
}

///|
/// The One-Pass Signature packet matching `sig`: version 3 for a v4 key
/// and version 6 for a v6 key. RFC 9580 §5.4 requires a v6 OPS to carry
/// the same hash salt as its Signature packet and the 32-octet signing
/// key fingerprint (in place of the v3 8-octet key id).
fn one_pass_sig_for(
  key : PrivateKey,
  sig : @packet.SignaturePacket,
  hash : @primitives.HashId,
) -> @packet.OnePassSigPacket raise {
  let v6 = key.primary.public.version() >= 6
  {
    version: if v6 {
      6
    } else {
      3
    },
    sig_type: sig.sig_type(),
    hash_algo: hash.number(),
    pub_algo: key.primary.public.algo(),
    key_id: if v6 {
      Bytes::new(0)
    } else {
      key.primary.public.key_id()
    },
    salt: if v6 {
      sig.salt()
    } else {
      Bytes::new(0)
    },
    fingerprint: if v6 {
      key.primary.public.fingerprint()
    } else {
      Bytes::new(0)
    },
    nested: false,
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
  let sig_type = sig_type_of(text_mode)
  let sig = make_document_signature(key, data, sig_type)
  let literal = @packet.LiteralPacket::binary(data, file_name="message.txt")
  let ops = one_pass_sig_for(key, sig, @primitives.Sha256)
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.OnePassSig, ops.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Literal, literal.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// Verify an inline-signed armored message; returns the literal data and
/// the verification status against `verifier`.
pub fn verify_inline(
  message : String,
  verifier : PublicKey,
  max_decompressed? : Int = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> (Bytes, VerifyStatus) raise {
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(block.data().exact_view())
  let (data, sig) = collect_data_sig(packets, None, None, max_decompressed)
  finish_inline_verify(data, sig, Some(verifier))
}

///|
/// Sign and encrypt in one step (inline signature inside SEIPD).
pub fn sign_and_encrypt(
  data : BytesView,
  signer : PrivateKey,
  recipients : Array[PublicKey],
  text_mode? : Bool,
  compress? : @compress.CompressedAlgo,
) -> String raise {
  let sig_type = sig_type_of(text_mode)
  let sig = make_document_signature(signer, data, sig_type)
  let literal = @packet.LiteralPacket::binary(data, file_name="message.txt")
  let ops = one_pass_sig_for(signer, sig, @primitives.Sha256)
  let inner = @packet.Writer::new()
  inner.bytes(
    @packet.serialize_packet(@packet.OnePassSig, ops.to_body().exact_view()).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Literal, literal.to_body().exact_view()).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  seal_to_recipients(
    maybe_compress_inner(inner.to_bytes().exact_view(), compress?).exact_view(),
    recipients,
  )
}

///|
/// Decrypt an armored message (password OR private keys) and verify an
/// inline signature against `verifier`. Returns (data, status).
pub fn decrypt_and_verify(
  message : String,
  decryption_keys : Array[PrivateKey],
  verifier : PublicKey?,
  max_decompressed? : Int = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> (Bytes, VerifyStatus) raise {
  // Try private-key decryption first, then fall back to no-password
  // path only when no keys given? Keep explicit: caller decides.
  let block = @armor.decode(message)
  let data_bytes = @armor.ArmorBlock::data(block)
  let packets = @packet.parse_packets(data_bytes.exact_view())
  // Try each key in turn. `decrypt_inner_with_key` is the same matcher the
  // plain private-key path uses, so it covers v6 PKESKs (fingerprint) and
  // v3 PKESKs (key id) as well as SEIPD v1 and v2 — this pipeline must not
  // be able to reject a message the library itself can produce.
  let mut inner_opt : Bytes? = None
  for key in decryption_keys {
    match decrypt_inner_with_key(packets, key) {
      Some(b) => {
        inner_opt = Some(b)
        break
      }
      None => ()
    }
  }
  // Keep the raw inner packet stream (it may carry a one-pass signature
  // around the literal data).
  let inner : Bytes = match inner_opt {
    Some(b) => b
    None => @error.fail("api: no matching decryption key")
  }
  // Walk inner packets: OPS? literal | compressed; trailing sig.
  let inner_packets = @packet.parse_packets(inner.exact_view())
  let (data, sig) = collect_data_sig(
    inner_packets,
    None,
    None,
    max_decompressed,
  )
  finish_inline_verify(data, sig, verifier)
}

///|
pub extend VerifyStatus with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend VerifyStatus with Eq::{not_equal, equal}
