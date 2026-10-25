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
/// The component that issues document signatures (task 2b): the primary
/// when it may sign, else the last sign-capable bound subkey in wire
/// order — mirroring how a cert-only GnuPG primary delegates document
/// signing to its signing subkey. Certifications, bindings and revocations
/// always come from the primary (RFC 9580 §5.2.1); only document-class
/// signatures (and their one-pass forms) may be subkey-issued.
///
/// A revoked or expired primary refuses to sign at all — signatures from
/// it would verify as KeyRevoked / Expired anyway. A candidate subkey is
/// skipped when it is revoked (mirroring `encryption_packet_at` — a
/// revoked component must not issue new signatures) or when its binding
/// lacks a verifying embedded Primary Key Binding: gpg refuses signatures
/// from a subkey that is not cross-certified, so issuing one here would
/// only produce a signature no major verifier accepts.
fn signing_packet(key : PrivateKey) -> @packet.SecretKeyPacket raise {
  let now = @primitives.unix_now()
  let pub_half = key.to_public()
  guard !pub_half.is_revoked(now) else {
    @error.fail("api: refusing to sign with a revoked key")
  }
  guard !pub_half.is_expired(now) else {
    @error.fail("api: refusing to sign with an expired primary key")
  }
  let primary_may_sign = match governing_flags(Some(key.self_signature())) {
    Some(f) => (f & FLAG_SIGN) != 0
    // Absent key flags mean "assume every capability" (the legacy rule).
    None => true
  }
  if primary_may_sign {
    return key.primary
  }
  let mut chosen : @packet.SecretKeyPacket? = None
  for c in key.subkeys {
    if !subkey_revoked_at(
        c.revocation,
        key.primary.public,
        c.secret.public,
        now,
      ) &&
      component_usable(c.secret.public, Some(c.binding), FLAG_SIGN, now) &&
      subkey_cross_certified(c.binding, key.primary.public, c.secret.public) {
      chosen = Some(c.secret)
    }
  }
  match chosen {
    Some(sk) => sk
    None =>
      @error.fail(
        "api: no component of this key may sign (primary is cert-only and no signing subkey is usable)",
      )
  }
}

///|
/// Build a v4 text signature with an explicit hash algorithm.
fn make_text_signature(
  signer : @packet.SecretKeyPacket,
  data : BytesView,
  hash : @primitives.HashId,
  created? : Int32,
) -> @packet.SignaturePacket raise {
  make_document_signature_with(
    signer,
    data,
    @packet.CanonicalTextDocument,
    hash,
    created?,
  )
}

///|
fn make_document_signature(
  signer : @packet.SecretKeyPacket,
  data : BytesView,
  sig_type : @packet.SigType,
  created? : Int32,
) -> @packet.SignaturePacket raise {
  make_document_signature_with(
    signer,
    data,
    sig_type,
    @primitives.Sha256,
    created?,
  )
}

///|
fn make_document_signature_with(
  signer : @packet.SecretKeyPacket,
  data : BytesView,
  sig_type : @packet.SigType,
  hash : @primitives.HashId,
  created? : Int32,
) -> @packet.SignaturePacket raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let v6 = signer.public.version() >= 6
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x02),
  ]
  if v6 {
    hashed.push(issuer_fingerprint_subpacket(signer.public))
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
        body: signer.public.key_id(),
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
    pub_algo: signer.public.algo(),
    hash_algo: hash.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt,
    sig_params: [],
  }
  let digest = document_hash(sig, data, sig_type)
  finish_signature(sig, signer, hash, digest.exact_view())
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
pub const DEFAULT_MAX_DECOMPRESSED_BYTES : Int32 = 536870912

///|
/// Decompress a compressed packet payload (shared by the verification and
/// decryption walks, F16) under a hard output cap.
fn decompress_payload(
  comp : @packet.CompressedPacket,
  max_out : Int32,
) -> Bytes raise {
  match comp.algo {
    0 => comp.data
    1 => @compress.zip_decompress_capped(comp.data.exact_view(), max_out)
    2 => @compress.zlib_decompress_capped(comp.data.exact_view(), max_out)
    // BZip2 (algorithm 3, which gpg can emit when configured) has no codec
    // in this pure-MoonBit implementation, for reading or writing; the
    // registry's bzip2 package is a native libbz2 binding this library
    // deliberately does not depend on. Fail with an explicit message
    // instead of a generic one (consolidation fix: the old comment claimed
    // "BZip2 is decode-only", which was never true).
    _ =>
      @error.fail(
        "api: unsupported compression algorithm \{comp.algo} (BZip2 is not implemented)",
      )
  }
}

///|
/// Optionally wrap an inner packet stream in a Compressed packet (M4).
/// Only ZIP/ZLIB have codecs here; BZip2 is unsupported in both directions
/// and `Uncompressed` means the caller passed something odd.
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
            "api: unsupported output compression algorithm \{algo.number()} (BZip2 is not implemented)",
          )
      }
  }
}

///|
/// Maximum nested Compressed packet depth on any packet walk (S03). gpg
/// emits at most one layer; three matches `extract_literal`'s precedent.
/// Without the cap, an algo-0 Compressed packet costs ~3 wire octets per
/// layer, so a few MB of untrusted input can drive hundreds of thousands
/// of recursion levels.
const MAX_COMPRESSED_DEPTH : Int32 = 3

///|
/// Walk a packet stream collecting the literal data and the signature,
/// recursing into compressed packets (they carry either [Literal] or the
/// [OPS, Literal, Sig] gpg -es shape). Returns the accumulated
/// (data, sig, remaining budget); unknown tags (e.g. OnePassSig) are
/// skipped.
///
/// `budget` is the *cumulative* cap on decompressed output across every
/// nested layer (S03): each decompression's cap is whatever remains of the
/// budget, so N nested layers cannot expand to N x `max_decompressed`.
/// Algo-0 packets perform no expansion and consume no budget.
fn collect_data_sig(
  packets : Array[@packet.RawPacket],
  data0 : Bytes?,
  sig0 : @packet.SignaturePacket?,
  max_decompressed : Int32,
  budget : Int32,
  depth : Int32,
) -> (Bytes?, @packet.SignaturePacket?, Int32) raise {
  let mut data = data0
  let mut sig = sig0
  let mut remaining = budget
  for p in packets {
    match p.tag() {
      @packet.Literal =>
        data = Some(@packet.LiteralPacket::parse(p.body().exact_view()).data())
      @packet.Signature =>
        sig = Some(@packet.SignaturePacket::parse(p.body().exact_view()))
      @packet.Compressed => {
        guard depth < MAX_COMPRESSED_DEPTH else {
          @error.fail(
            "api: compressed packets nested more than \{MAX_COMPRESSED_DEPTH} levels deep",
          )
        }
        let comp = @packet.CompressedPacket::parse(p.body().exact_view())
        let inner : Bytes = match comp.algo {
          0 => comp.data
          _ => {
            let cap = if remaining < max_decompressed {
              remaining
            } else {
              max_decompressed
            }
            let out = decompress_payload(comp, cap)
            remaining = remaining - out.length()
            out
          }
        }
        let (d2, s2, rem2) = collect_data_sig(
          @packet.parse_packets(inner.exact_view()),
          data,
          sig,
          max_decompressed,
          remaining,
          depth + 1,
        )
        data = d2
        sig = s2
        remaining = rem2
      }
      _ => ()
    }
  }
  (data, sig, remaining)
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
///
/// `created` is the signature creation time in seconds since 1970; without it
/// the current time is used. Passing the time makes the signature
/// reproducible for RSA PKCS#1 v1.5 and Ed25519 keys, which sign
/// deterministically (for example for reproducible builds).
pub fn sign_detached(
  data : BytesView,
  key : PrivateKey,
  text_mode? : Bool,
  created? : Int32,
) -> String raise {
  let sig_type = sig_type_of(text_mode)
  let signer = signing_packet(key)
  let sig = make_document_signature(signer, data, sig_type, created?)
  @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
}

///|
/// Verification outcome, mirroring gopenpgp's status codes
/// (OK / NOT_SIGNED / NO_VERIFIER / FAILED) plus the lifecycle outcomes
/// gopenpgp v3 folds into a rejected signature.
pub(all) enum VerifyStatus {
  /// Signature verified against the given key.
  Ok
  /// The message carried no signature at all.
  NotSigned
  /// The signature belongs to a key we cannot verify with.
  NoVerifier
  /// A matching key was present but verification failed.
  Failed
  /// The signature is cryptographically valid but the signing key (or the
  /// signing subkey) is revoked — never `Ok` (S02; gopenpgp v3 rejects
  /// signatures from revoked keys).
  KeyRevoked
  /// The signature is cryptographically valid but the signing key or the
  /// signature itself has expired.
  Expired
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
  // RFC 9580 §5.2.3.6 (S01): an unrecognized subpacket marked critical
  // puts the whole signature in error — before any cryptography runs.
  if sig.has_unknown_critical_subpacket() {
    return Failed
  }
  // Which key of the transferable key issued this signature? The issuer
  // key id is matched against the primary and EVERY bound subkey (N2);
  // `comp` carries the matched subkey's own binding/revocation into the
  // lifecycle gate.
  let issuer = sig.issuer_key_id()
  let primary_id = verifier.primary.key_id()
  let signer : (@packet.PublicKeyPacket, SubkeyCert?)? = match issuer {
    Some(id) =>
      if primary_id.equal(id) {
        Some((verifier.primary, None))
      } else {
        // Lenient on purpose (F15): a subkey whose id cannot be computed
        // merely drops out of the candidate match.
        let mut hit : (@packet.PublicKeyPacket, SubkeyCert?)? = None
        for c in verifier.subkeys {
          let sid = c.key.key_id() catch { _ => Bytes::new(0) }
          if sid.length() > 0 && sid.equal(id) {
            hit = Some((c.key, Some(c)))
            break
          }
        }
        hit
      }
    None => Some((verifier.primary, None))
  }
  match signer {
    None => NoVerifier
    Some((signer_pk, comp)) => {
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
        lifecycle_status(sig, verifier, comp)
      } else {
        Failed
      }
    }
  }
}

///|
/// Lifecycle gate after a cryptographically valid signature (S02): a
/// signature from a revoked or expired key is not `Ok`. With `now = 0`
/// (clock-less targets) the expiry checks are skipped but revocation
/// signatures are still cryptographically validated — the same degradation
/// `is_revoked` itself documents.
fn lifecycle_status(
  sig : @packet.SignaturePacket,
  verifier : PublicKey,
  comp : SubkeyCert?,
) -> VerifyStatus {
  let now = @primitives.unix_now()
  if verifier.is_revoked(now) {
    return KeyRevoked
  }
  match comp {
    Some(c) => {
      if subkey_revoked_at(c.revocation, verifier.primary, c.key, now) {
        return KeyRevoked
      }
      // A subkey only exists as part of its certificate: an expired
      // primary leaves the subkey's signatures without a current
      // certification too (N7).
      if verifier.is_expired(now) {
        return Expired
      }
      if packet_expired_at(c.key, Some(c.binding), now) ||
        sig_expired_opt(Some(c.binding), now) {
        return Expired
      }
    }
    None => if verifier.is_expired(now) { return Expired }
  }
  if sig_expired_at(sig, now) {
    return Expired
  }
  Ok
}

///|
/// The One-Pass Signature packet matching `sig`: version 3 for a v4 key
/// and version 6 for a v6 key. RFC 9580 §5.4 requires a v6 OPS to carry
/// the same hash salt as its Signature packet and the 32-octet signing
/// key fingerprint (in place of the v3 8-octet key id).
fn one_pass_sig_for(
  signer : @packet.SecretKeyPacket,
  sig : @packet.SignaturePacket,
  hash : @primitives.HashId,
) -> @packet.OnePassSigPacket raise {
  let v6 = signer.public.version() >= 6
  {
    version: if v6 {
      6
    } else {
      3
    },
    sig_type: sig.sig_type(),
    hash_algo: hash.number(),
    pub_algo: signer.public.algo(),
    key_id: if v6 {
      Bytes::new(0)
    } else {
      signer.public.key_id()
    },
    salt: if v6 {
      sig.salt()
    } else {
      Bytes::new(0)
    },
    fingerprint: if v6 {
      signer.public.fingerprint()
    } else {
      Bytes::new(0)
    },
    nested: false,
  }
}

///|
/// Create an inline-signed, armored message: One-Pass-Signature ||
/// Literal || Signature.
///
/// `created` is the signature creation time in seconds since 1970; without it
/// the current time is used (see `sign_detached` — deterministic for
/// RSA/Ed25519 keys, so the message becomes reproducible). `file_name` names
/// the literal packet (N9; default "message.txt").
pub fn sign_inline(
  data : BytesView,
  key : PrivateKey,
  text_mode? : Bool,
  created? : Int32,
  file_name? : String,
) -> String raise {
  let sig_type = sig_type_of(text_mode)
  let signer = signing_packet(key)
  let sig = make_document_signature(signer, data, sig_type, created?)
  let literal = @packet.LiteralPacket::binary(
    data,
    file_name=file_name.unwrap_or("message.txt"),
  )
  let ops = one_pass_sig_for(signer, sig, @primitives.Sha256)
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
  max_decompressed~ : Int32 = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> (Bytes, VerifyStatus) raise {
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(block.data().exact_view())
  let (data, sig, _budget) = collect_data_sig(
    packets,
    None,
    None,
    max_decompressed,
    max_decompressed,
    0,
  )
  finish_inline_verify(data, sig, Some(verifier))
}

///|
/// Sign and encrypt in one step (inline signature inside SEIPD).
///
/// `created` is the signature creation time in seconds since 1970; without it
/// the current time is used (see `sign_detached`). `file_name` names the
/// literal packet (N9; default "message.txt").
pub fn sign_and_encrypt(
  data : BytesView,
  signer : PrivateKey,
  recipients : Array[PublicKey],
  text_mode? : Bool,
  compress? : @compress.CompressedAlgo,
  created? : Int32,
  file_name? : String,
) -> String raise {
  let sig_type = sig_type_of(text_mode)
  let signing_component = signing_packet(signer)
  let sig = make_document_signature(signing_component, data, sig_type, created?)
  let literal = @packet.LiteralPacket::binary(
    data,
    file_name=file_name.unwrap_or("message.txt"),
  )
  let ops = one_pass_sig_for(signing_component, sig, @primitives.Sha256)
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
  max_decompressed~ : Int32 = DEFAULT_MAX_DECOMPRESSED_BYTES,
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
  let (data, sig, _budget) = collect_data_sig(
    inner_packets,
    None,
    None,
    max_decompressed,
    max_decompressed,
    0,
  )
  finish_inline_verify(data, sig, verifier)
}

///|
pub extend VerifyStatus with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend VerifyStatus with Eq::{not_equal, equal}
