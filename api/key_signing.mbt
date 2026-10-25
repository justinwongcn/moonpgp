///|
/// RSA MPI helpers: extract n/e/d/p/q/u as BigInts.
fn rsa_public_parts(p : @packet.PublicKeyPacket) -> (BigInt, BigInt) raise {
  let params = p.params()
  guard params.length() == 2 else {
    @error.fail("api: bad RSA public parameters")
  }
  (
    BigInt::from_octets(params[0].exact_view(), signum=1),
    BigInt::from_octets(params[1].exact_view(), signum=1),
  )
}

///|
fn rsa_secret_parts(p : @packet.SecretKeyPacket) -> @pki.RsaPrivateKey raise {
  guard p.s2k_usage == 0 else {
    @error.fail("api: secret key material is locked; unlock it first")
  }
  let (n, e) = rsa_public_parts(p.public)
  let r = @packet.Reader::new(p.secret_material.exact_view())
  let d = BigInt::from_octets(r.read_mpi().exact_view(), signum=1)
  let pbig = BigInt::from_octets(r.read_mpi().exact_view(), signum=1)
  let qbig = BigInt::from_octets(r.read_mpi().exact_view(), signum=1)
  let u = BigInt::from_octets(r.read_mpi().exact_view(), signum=1)
  @pki.RsaPrivateKey::{ public: { n, e, }, d, p: pbig, q: qbig, u, }
}

///|

///|
/// EdDSA legacy secret parts: one MPI holding the 32-octet seed.
fn eddsa_secret_parts(
  p : @packet.SecretKeyPacket,
) -> @pki.Ed25519SecretKey raise {
  guard p.s2k_usage == 0 else {
    @error.fail("api: secret key material is locked; unlock it first")
  }
  let r = @packet.Reader::new(p.secret_material.exact_view())
  // MPI strips leading zero octets; a seed whose first octet is 0x00
  // (probability 1/256) arrives as 31 bytes. Pad back to the fixed
  // 32-octet scalar on read.
  let seed_mpi = r.read_mpi()
  guard seed_mpi.length() <= 32 else {
    @error.fail("api: bad EdDSA seed length")
  }
  let seed = @primitives.pad_left(seed_mpi.exact_view(), 32)
  let point = p.public.params()[1]
  guard point.length() == 33 else { @error.fail("api: bad EdDSA point") }
  @pki.Ed25519SecretKey::{ seed, public: point[1:point.length()].to_owned(), }
}

///|
/// Native Ed25519 secret parts: the secret material is 32 raw octets (no
/// MPI, no framing — RFC 9580 §5.5.5.9) and the public point is the
/// single 32-octet native parameter. A v4 secret key packet appends the
/// 2-octet checksum after the raw octets (v6 does not); strip it.
fn ed25519_native_secret_parts(
  p : @packet.SecretKeyPacket,
) -> @pki.Ed25519SecretKey raise {
  guard p.s2k_usage == 0 else {
    @error.fail("api: secret key material is locked; unlock it first")
  }
  let want = if p.public.version() >= 6 { 32 } else { 34 }
  guard p.secret_material.length() == want else {
    @error.fail("api: bad Ed25519 secret key length")
  }
  let seed = if want == 32 {
    p.secret_material
  } else {
    p.secret_material[0:32].to_owned()
  }
  let params = p.public.params()
  guard params.length() == 1 && params[0].length() == 32 else {
    @error.fail("api: bad Ed25519 public key")
  }
  @pki.Ed25519SecretKey::{ seed, public: params[0], }
}

///|
/// Sign `digest` with the key's algorithm; returns the algorithm-specific
/// signature material in wire order (RSA: DigestInfo-encoded EM; EdDSA
/// legacy: r and s MPIs; Ed25519 v6: one raw 64-octet blob).
fn sign_digest_with_key(
  secret_packet : @packet.SecretKeyPacket,
  hash : @primitives.HashId,
  digest : BytesView,
) -> Array[Bytes] raise {
  match secret_packet.public.algo() {
    @packet.EdDsaLegacy => {
      let ed = eddsa_secret_parts(secret_packet)
      let sig64 = ed.sign(digest)
      [sig64[0:32].to_owned(), sig64[32:64].to_owned()]
    }
    @packet.Ed25519 => {
      let ed = ed25519_native_secret_parts(secret_packet)
      [ed.sign(digest)]
    }
    _ => {
      let rsa = rsa_secret_parts(secret_packet)
      [rsa.pkcs1_v15_sign(hash, digest)]
    }
  }
}

///|
/// Verify algorithm-specific signature material against a public key packet.
fn verify_sig_material(
  pub_packet : @packet.PublicKeyPacket,
  hash : @primitives.HashId,
  digest : BytesView,
  sig_params : Array[Bytes],
) -> Bool raise {
  match pub_packet.algo() {
    @packet.EdDsaLegacy => {
      guard sig_params.length() == 2 else { return false }
      let point = pub_packet.params()[1]
      guard point.length() == 33 && point[0] == b'\x40' else { return false }
      let r = @primitives.pad_left(sig_params[0].exact_view(), 32)
      let sv = @primitives.pad_left(sig_params[1].exact_view(), 32)
      let pub_bytes = point[1:point.length()]
      let pk = @pki.ed25519_public_key(pub_bytes.exact_view())
      let sig64 = r.add(sv)
      pk.verify(digest, sig64.exact_view())
    }
    @packet.Ed25519 => {
      // v6: one raw 64-octet signature over a 32-octet native point.
      guard sig_params.length() == 1 && sig_params[0].length() == 64 else {
        return false
      }
      let params = pub_packet.params()
      guard params.length() == 1 && params[0].length() == 32 else {
        return false
      }
      let pk = @pki.ed25519_public_key(params[0].exact_view())
      pk.verify(digest, sig_params[0].exact_view())
    }
    _ => {
      guard sig_params.length() == 1 else { return false }
      let rsa = rsa_public_key(pub_packet)
      rsa.pkcs1_v15_verify(hash, digest, sig_params[0].exact_view())
    }
  }
}

///|
/// Preferred algorithm subpackets used in our self-signatures.
fn preferred_subpackets(v6 : Bool) -> Array[@packet.SigSubpacket] {
  let out : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: @packet.SIGSUB_PREFERRED_SYM_ALGOS,
      body: Bytes::from_array([9, 8, 7]),
    },
    {
      critical: false,
      sub_type: @packet.SIGSUB_PREFERRED_HASH_ALGOS,
      body: Bytes::from_array([10, 9, 8]),
    },
    {
      critical: false,
      sub_type: @packet.SIGSUB_PREFERRED_COMP_ALGOS,
      body: Bytes::from_array([2, 1, 0]),
    },
    {
      critical: false,
      sub_type: @packet.SIGSUB_FEATURES,
      // §5.2.3.32: v1 SEIPD is always supported; v6 keys additionally
      // advertise v2 SEIPD so peers know they may send the AEAD shape.
      body: Bytes::from_array([
        (if v6 {
          @packet.FEATURE_SEIPD_V1 | @packet.FEATURE_SEIPD_V2
        } else {
          @packet.FEATURE_SEIPD_V1
        }).to_byte(),
      ]),
    },
  ]
  if v6 {
    // §5.2.3.15: AES-256/OCB, AES-256/GCM, AES-128/OCB (the mandatory
    // AES-128/OCB pair is implicit and need not be listed).
    out.push({
      critical: false,
      sub_type: @packet.SIGSUB_PREFERRED_AEAD,
      body: Bytes::from_array([9, 2, 9, 3, 7, 2]),
    })
  }
  out
}

///|
fn creation_subpacket(now : Int32) -> @packet.SigSubpacket {
  {
    critical: false,
    sub_type: @packet.SIGSUB_CREATION_TIME,
    body: Bytes::makei(4, i => (now >> (24 - i * 8)).to_byte()),
  }
}

///|
fn key_flags_subpacket(flags : Int32) -> @packet.SigSubpacket {
  {
    critical: false,
    sub_type: @packet.SIGSUB_KEY_FLAGS,
    body: Bytes::from_array([flags.to_byte()]),
  }
}

///|
/// Attach the fast-hash (first two octets of the DIGEST, RFC 9580
/// §5.2.4) and the algorithm-specific signature material.
fn finish_signature(
  sig : @packet.SignaturePacket,
  secret_packet : @packet.SecretKeyPacket,
  hash : @primitives.HashId,
  digest : BytesView,
) -> @packet.SignaturePacket raise {
  let params = sign_digest_with_key(secret_packet, hash, digest)
  let fast = (digest[0].to_int() << 8) | digest[1].to_int()
  { ..sig, fast_hash: fast, sig_params: params, }
}

///|
/// Create a self-certification (PositiveCertification, 0x13) of `user_id`
/// over the primary key.
fn make_self_signature(
  secret_packet : @packet.SecretKeyPacket,
  pub_packet : @packet.PublicKeyPacket,
  user_id : String,
  now : Int32,
) -> @packet.SignaturePacket raise {
  let v6 = pub_packet.version() >= 6
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x03),
    ..preferred_subpackets(v6),
  ]
  if v6 {
    // §5.2.3.12/33: v6 keys identify the issuer by fingerprint.
    hashed.push(issuer_fingerprint_subpacket(pub_packet))
  }
  let unhashed : Array[@packet.SigSubpacket] = if v6 {
    []
  } else {
    [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: pub_packet.key_id(),
      },
    ]
  }
  let salt : Bytes = if v6 {
    @primitives.random_bytes(
      @packet.salt_size_of_hash(@primitives.Sha256.number()),
    )
  } else {
    Bytes::new(0)
  }
  let sig : @packet.SignaturePacket = {
    version: if v6 {
      6
    } else {
      4
    },
    sig_type: @packet.PositiveCertification,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt,
    sig_params: [],
  }
  let digest = hash_certification(sig, pub_packet, user_id)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Create the Direct Key signature (type 0x1F) over the primary key that
/// RFC 9580 §5.2.3.10 requires before a v6 key may be used.
fn make_direct_key_signature(
  secret_packet : @packet.SecretKeyPacket,
  pub_packet : @packet.PublicKeyPacket,
  now : Int32,
) -> @packet.SignaturePacket raise {
  guard pub_packet.version() >= 6 else {
    @error.fail("api: direct key signatures are a v6 construct")
  }
  let hashed : Array[@packet.SigSubpacket] = [
    { ..creation_subpacket(now), critical: true, },
    key_flags_subpacket(0x03),
    ..preferred_subpackets(true),
    issuer_fingerprint_subpacket(pub_packet),
  ]
  let sig : @packet.SignaturePacket = {
    version: 6,
    sig_type: @packet.DirectSignature,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: [],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: @primitives.random_bytes(
      @packet.salt_size_of_hash(@primitives.Sha256.number()),
    ),
    sig_params: [],
  }
  let digest = hash_direct_key(sig, pub_packet)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Create a subkey binding signature (0x18): version 4 for a v4 primary
/// key, version 6 (with a hash salt and the fingerprint issuer subpacket)
/// for a v6 one. A v6 primary key may only certify v6 subkeys.
fn make_binding_signature(
  secret_packet : @packet.SecretKeyPacket,
  primary_pub : @packet.PublicKeyPacket,
  subkey_pub : @packet.PublicKeyPacket,
  now : Int32,
) -> @packet.SignaturePacket raise {
  let v6 = primary_pub.version() >= 6
  guard !v6 || subkey_pub.version() >= 6 else {
    @error.fail("api: a v6 primary key must certify v6 subkeys")
  }
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x0C),
    ..preferred_subpackets(v6),
  ]
  if v6 {
    hashed.push(issuer_fingerprint_subpacket(primary_pub))
  }
  let unhashed : Array[@packet.SigSubpacket] = if v6 {
    []
  } else {
    [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: primary_pub.key_id(),
      },
    ]
  }
  let sig : @packet.SignaturePacket = {
    version: if v6 {
      6
    } else {
      4
    },
    salt: if v6 {
      @primitives.random_bytes(
        @packet.salt_size_of_hash(@primitives.Sha256.number()),
      )
    } else {
      Bytes::new(0)
    },
    sig_type: @packet.SubkeyBinding,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    sig_params: [],
  }
  let digest = hash_binding(sig, primary_pub, subkey_pub)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Frame a key packet for certification hashing: v4 uses 0x99 + u16
/// length, v6 uses 0x9B + u32 length (RFC 9580 §5.2.4).
fn write_key_framing(
  w : @packet.Writer,
  pub_packet : @packet.PublicKeyPacket,
) -> Unit raise {
  let body = pub_packet.to_body()
  if pub_packet.version() >= 6 {
    w.u8(0x9B)
    w.u32(body.length())
    w.bytes(body.exact_view())
  } else {
    // v4 hash framing encodes the packet length as u16 (F09): a larger key
    // packet would silently truncate and produce an unverifiable signature.
    guard body.length() <= 0xFFFF else {
      @error.fail("api: key packet too large")
    }
    w.u8(0x99)
    w.u16(body.length())
    w.bytes(body.exact_view())
  }
}

///|
/// Hash data for a User ID certification.
fn hash_certification(
  sig : @packet.SignaturePacket,
  pub_packet : @packet.PublicKeyPacket,
  user_id : String,
) -> Bytes raise {
  let uid = @primitives.utf8_bytes(user_id)
  let w = @packet.Writer::new()
  write_key_framing(w, pub_packet)
  w.u8(0xB4)
  w.u32(uid.length())
  w.bytes(uid.exact_view())
  finish_signed_digest(sig, w.to_bytes().exact_view())
}

///|
/// Hash data for a Direct Key signature: the framed key packet alone.
fn hash_direct_key(
  sig : @packet.SignaturePacket,
  pub_packet : @packet.PublicKeyPacket,
) -> Bytes raise {
  let w = @packet.Writer::new()
  write_key_framing(w, pub_packet)
  finish_signed_digest(sig, w.to_bytes().exact_view())
}

///|
/// Hash data for a subkey binding signature.
fn hash_binding(
  sig : @packet.SignaturePacket,
  primary_pub : @packet.PublicKeyPacket,
  subkey_pub : @packet.PublicKeyPacket,
) -> Bytes raise {
  let w = @packet.Writer::new()
  write_key_framing(w, primary_pub)
  write_key_framing(w, subkey_pub)
  finish_signed_digest(sig, w.to_bytes().exact_view())
}

///|
/// Verify a self-certification or binding signature over key material.
/// Deliberately public (F14 review decision): it is the key-management
/// entry point for validating third-party keys, exercised from outside
/// the package by the gopenpgp self-certification cross-validation tests.
pub fn verify_key_signature(
  sig : @packet.SignaturePacket,
  signer_pub : @packet.PublicKeyPacket,
  certified_pub : @packet.PublicKeyPacket,
  user_id? : String,
  direct~ : Bool = false,
) -> Bool raise {
  // Same critical rule as document verification (S01): a certification,
  // binding or revocation carrying an unrecognized critical subpacket is
  // in error. For revocations this is the safe direction — an invalid
  // revocation cannot disable a key.
  if sig.has_unknown_critical_subpacket() {
    return false
  }
  let digest : Bytes = if direct {
    hash_direct_key(sig, certified_pub)
  } else {
    match user_id {
      Some(uid) => hash_certification(sig, certified_pub, uid)
      None => hash_binding(sig, signer_pub, certified_pub)
    }
  }
  let hash_id = match @primitives.hash_id_of_number(sig.hash_algo()) {
    Some(h) => h
    None => return false
  }
  verify_sig_material(
    signer_pub,
    hash_id,
    digest.exact_view(),
    sig.sig_params(),
  ) catch {
    _ => false
  }
}

///|
/// RSA public key view of a public key packet.
fn rsa_public_key(
  pub_packet : @packet.PublicKeyPacket,
) -> @pki.RsaPublicKey raise {
  let (n, e) = rsa_public_parts(pub_packet)
  @pki.RsaPublicKey::{ n, e, }
}
