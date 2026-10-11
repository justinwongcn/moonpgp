///|
/// An OpenPGP transferable private key: v4 RSA primary key, one User ID
/// with its self-certification, and an RSA encryption subkey with its
/// binding signature. Fields are read-only from outside the package —
/// obtain keys through `generate_key` / `from_armored` / `from_bytes` and
/// mutate them through `lock` / `unlock` so the cross-field invariants hold.
pub struct PrivateKey {
  primary : @packet.SecretKeyPacket
  /// All certified User IDs, in wire order (M5). A bare v6 key carries
  /// none and is self-signed by its Direct Key signature instead.
  user_ids : Array[UserIdBinding]
  /// v6 keys: the Direct Key signature (type 0x1F) over the primary key,
  /// required by RFC 9580 §5.2.3.10 before a v6 key may be used.
  direct_signature : @packet.SignaturePacket?
  encryption_subkey : @packet.SecretKeyPacket?
  subkey_binding : @packet.SignaturePacket?
  /// Primary-key revocation signatures (type 0x20) found on import;
  /// verified lazily by `is_revoked` (their validity is time-dependent).
  revocations : Array[@packet.SignaturePacket]
  /// Subkey revocation signature (type 0x28), when the wire had one.
  subkey_revocation : @packet.SignaturePacket?
} derive(Debug)

///|
/// The public half of a transferable key. Read-only like `PrivateKey`;
/// obtain values via `to_public` / `from_armored` / `from_bytes`.
pub struct PublicKey {
  primary : @packet.PublicKeyPacket
  /// All certified User IDs, in wire order (M5).
  user_ids : Array[UserIdBinding]
  direct_signature : @packet.SignaturePacket?
  encryption_subkey : @packet.PublicKeyPacket?
  subkey_binding : @packet.SignaturePacket?
  /// Primary-key revocation signatures (type 0x20) found on import.
  revocations : Array[@packet.SignaturePacket]
  /// Subkey revocation signature (type 0x28), when the wire had one.
  subkey_revocation : @packet.SignaturePacket?
} derive(Debug)

///|
/// One certified User ID: the identifier plus the self-signature that
/// binds it to the primary key.
pub(all) struct UserIdBinding {
  user_id : String
  self_signature : @packet.SignaturePacket
} derive(Debug)

///|
pub extend UserIdBinding with @moonbitlang/core/debug.Debug::{to_repr}

///|
/// 8-octet key id of the primary key (low 64 bits of the v4 fingerprint).
pub fn PrivateKey::key_id(self : PrivateKey) -> Bytes raise {
  self.primary.public.key_id()
}

///|
/// 20-octet v4 fingerprint of the primary key.
pub fn PrivateKey::fingerprint(self : PrivateKey) -> Bytes raise {
  self.primary.public.fingerprint()
}

///|
/// The primary (first) certified User ID string; empty for a bare v6 key.
pub fn PrivateKey::user_id(self : PrivateKey) -> String {
  match self.user_ids {
    [] => ""
    [first, ..] => first.user_id
  }
}

///|
/// The key-level self-signature: the first User ID certification, or the
/// Direct Key signature of a bare v6 key. Import guarantees one of the
/// two exists, so this never aborts on a key obtained through
/// `from_bytes`/`from_armored`/`generate_*`.
pub fn PrivateKey::self_signature(self : PrivateKey) -> @packet.SignaturePacket {
  match self.user_ids {
    [first, ..] => first.self_signature
    [] =>
      match self.direct_signature {
        Some(d) => d
        None => abort("api: key has no self-signature")
      }
  }
}

///|
/// 8-octet key id of the primary key.
pub fn PublicKey::key_id(self : PublicKey) -> Bytes raise {
  self.primary.key_id()
}

///|
/// 20-octet v4 fingerprint of the primary key.
pub fn PublicKey::fingerprint(self : PublicKey) -> Bytes raise {
  self.primary.fingerprint()
}

///|
/// The primary (first) certified User ID string; empty for a bare v6 key.
pub fn PublicKey::user_id(self : PublicKey) -> String {
  match self.user_ids {
    [] => ""
    [first, ..] => first.user_id
  }
}

///|
/// The key-level self-signature: the first User ID certification, or the
/// Direct Key signature of a bare v6 key. Import guarantees one of the
/// two exists, so this never aborts on a key obtained through
/// `from_bytes`/`from_armored`/`generate_*`.
pub fn PublicKey::self_signature(self : PublicKey) -> @packet.SignaturePacket {
  match self.user_ids {
    [first, ..] => first.self_signature
    [] =>
      match self.direct_signature {
        Some(d) => d
        None => abort("api: key has no self-signature")
      }
  }
}

///|
/// The public key packet of an encryption-capable key: the subkey when
/// present, otherwise the primary key.
pub fn PublicKey::encryption_key(self : PublicKey) -> @packet.PublicKeyPacket? {
  match self.encryption_subkey {
    Some(k) => Some(k)
    None => if self.primary.algo().is_rsa() { Some(self.primary) } else { None }
  }
}

///|
/// Strip the secret material, producing a transferable public key.
pub fn PrivateKey::to_public(self : PrivateKey) -> PublicKey {
  PublicKey::{
    primary: self.primary.public,
    user_ids: self.user_ids,
    direct_signature: self.direct_signature,
    encryption_subkey: match self.encryption_subkey {
      Some(sk) => Some(sk.public)
      None => None
    },
    subkey_binding: self.subkey_binding,
    revocations: self.revocations,
    subkey_revocation: self.subkey_revocation,
  }
}

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
/// v6 Ed25519 secret parts: the secret material is 32 raw octets (no
/// MPI, no checksum — RFC 9580 §5.5.5.9) and the public point is the
/// single 32-octet native parameter.
fn ed25519_v6_secret_parts(
  p : @packet.SecretKeyPacket,
) -> @pki.Ed25519SecretKey raise {
  guard p.s2k_usage == 0 else {
    @error.fail("api: secret key material is locked; unlock it first")
  }
  guard p.secret_material.length() == 32 else {
    @error.fail("api: bad v6 Ed25519 secret key length")
  }
  let params = p.public.params()
  guard params.length() == 1 && params[0].length() == 32 else {
    @error.fail("api: bad v6 Ed25519 public key")
  }
  @pki.Ed25519SecretKey::{ seed: p.secret_material, public: params[0], }
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
      let ed = ed25519_v6_secret_parts(secret_packet)
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
fn build_eddsa_secret_key_packet(
  seed : Bytes,
  creation : Int,
) -> @packet.SecretKeyPacket raise {
  let ed = @pki.ed25519_public_of_seed(seed.exact_view())
  // Public params: length-prefixed OID, MPI of the point (0x40 || key).
  let point = Bytes::from_array([0x40]).add(ed.public)
  let params : Array[Bytes] = [@pki.ed25519_oid(), point]
  let pub_packet : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: creation,
    algo: @packet.EdDsaLegacy,
    params,
  }
  // Secret material: MPI(seed) + 2-octet checksum.
  let sw = @packet.Writer::new()
  sw.mpi(seed.exact_view())
  let mpi_bytes = sw.to_bytes()
  let w2 = @packet.Writer::new()
  w2.bytes(mpi_bytes.exact_view())
  w2.u16(@packet.session_key_checksum(mpi_bytes.exact_view()))
  @packet.SecretKeyPacket::{
    public: pub_packet,
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: w2.to_bytes(),
    dummy: false,
  }
}

///|
/// Build a v6 Ed25519 secret key packet (RFC 9580 §5.5.2.3/§5.5.5.9):
/// native 32-octet public point, 32 raw octets of secret seed and no
/// trailing checksum.
fn build_ed25519_v6_secret_key_packet(
  seed : Bytes,
  creation : Int,
) -> @packet.SecretKeyPacket raise {
  guard seed.length() == 32 else {
    @error.fail("api: Ed25519 seed must be 32 octets")
  }
  let ed = @pki.ed25519_public_of_seed(seed.exact_view())
  let params : Array[Bytes] = [ed.public]
  let pub_packet : @packet.PublicKeyPacket = {
    version: 6,
    creation_time: creation,
    algo: @packet.Ed25519,
    params,
  }
  @packet.SecretKeyPacket::{
    public: pub_packet,
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: seed,
    dummy: false,
  }
}

///|
fn build_rsa_secret_key_packet(
  key : @pki.RsaPrivateKey,
  creation : Int,
) -> @packet.SecretKeyPacket {
  // Public part: MPI(n), MPI(e).
  let params : Array[Bytes] = [
    @pki.i2osp(key.public.n, (key.public.n.bit_length() + 7) / 8),
    @pki.i2osp(key.public.e, (key.public.e.bit_length() + 7) / 8),
  ]
  let pub_packet : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: creation,
    algo: @packet.RsaEncryptOrSign,
    params,
  }
  // Secret material: MPI(d) MPI(p) MPI(q) MPI(u) + 2-octet checksum.
  let sw = @packet.Writer::new()
  sw.mpi(@pki.i2osp(key.d, (key.d.bit_length() + 7) / 8).exact_view())
  sw.mpi(@pki.i2osp(key.p, (key.p.bit_length() + 7) / 8).exact_view())
  sw.mpi(@pki.i2osp(key.q, (key.q.bit_length() + 7) / 8).exact_view())
  sw.mpi(@pki.i2osp(key.u, (key.u.bit_length() + 7) / 8).exact_view())
  let mpi_bytes = sw.to_bytes()
  let w2 = @packet.Writer::new()
  w2.bytes(mpi_bytes.exact_view())
  w2.u16(@packet.session_key_checksum(mpi_bytes.exact_view()))
  @packet.SecretKeyPacket::{
    public: pub_packet,
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: w2.to_bytes(),
    dummy: false,
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
fn creation_subpacket(now : Int) -> @packet.SigSubpacket {
  {
    critical: false,
    sub_type: @packet.SIGSUB_CREATION_TIME,
    body: Bytes::makei(4, i => (now >> (24 - i * 8)).to_byte()),
  }
}

///|
fn key_flags_subpacket(flags : Int) -> @packet.SigSubpacket {
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
  now : Int,
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
  now : Int,
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
  now : Int,
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
  direct? : Bool = false,
) -> Bool raise {
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
/// Generate a fresh transferable key: RSA primary (certify+sign) with a
/// User ID self-certification plus an RSA encryption subkey.
pub fn generate_key(user_id : String, bits? : Int = 3072) -> PrivateKey raise {
  // Int truncation of the Int64 wall clock is wire-safe (Writer::u32 emits
  // the two's-complement low 32 bits, which is the correct u32 epoch past
  // 2038) but stays negative in memory; only date FORMATTING from this
  // value would be wrong (F09, documented limitation).
  let now = @primitives.unix_now().to_int()
  let sub_bits = if bits >= 4096 { 3072 } else { bits }
  let primary_rsa = @pki.generate_rsa_key(bits~)
  let primary = build_rsa_secret_key_packet(primary_rsa, now)
  let self_sig = make_self_signature(primary, primary.public, user_id, now)
  let sub_rsa = @pki.generate_rsa_key(bits=sub_bits)
  let subkey = build_rsa_secret_key_packet(sub_rsa, now)
  let binding = make_binding_signature(
    primary,
    primary.public,
    subkey.public,
    now,
  )
  PrivateKey::{
    primary,
    user_ids: [UserIdBinding::{ user_id, self_signature: self_sig, }],
    direct_signature: None,
    encryption_subkey: Some(subkey),
    subkey_binding: Some(binding),
    revocations: [],
    subkey_revocation: None,
  }
}

///|
/// Serialize to binary packets: SecretKey || [DirectKeySig] ||
/// [UserID || cert] || [SecretSubkey || binding ]. A v6 key without a
/// User ID writes only the Direct Key signature.
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  match self.direct_signature {
    Some(b) =>
      w.bytes(
        @packet.serialize_packet(@packet.Signature, b.to_body().exact_view()).exact_view(),
      )
    None => ()
  }
  // Emit every certified User ID with its own certification (M5). A
  // bare v6 key emits none here; its Direct Key signature was already
  // written above.
  for binding in self.user_ids {
    let uid = @primitives.utf8_bytes(binding.user_id)
    w.bytes(
      @packet.serialize_packet(@packet.UserId, uid.exact_view()).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(
        @packet.Signature,
        binding.self_signature.to_body().exact_view(),
      ).exact_view(),
    )
  }
  match self.encryption_subkey {
    Some(subkey) => {
      w.bytes(
        @packet.serialize_packet(
          @packet.SecretSubkey,
          subkey.to_body().exact_view(),
        ).exact_view(),
      )
      match self.subkey_binding {
        Some(b) =>
          w.bytes(
            @packet.serialize_packet(
              @packet.Signature,
              b.to_body().exact_view(),
            ).exact_view(),
          )
        None => ()
      }
    }
    None => ()
  }
  w.to_bytes()
}

///|
/// Export as ASCII-armored private key block.
pub fn PrivateKey::to_armored(self : PrivateKey) -> String {
  @armor.PrivateKey.encode(self.to_bytes().exact_view())
}

///|
/// The Preferred AEAD Ciphersuites advertised by a key as (cipher, AEAD)
/// id pairs, most preferred first (RFC 9580 §5.2.3.15). Reads the
/// self-signature first, then the Direct Key signature of a v6 key, and
/// returns an empty list when the key advertises none.
pub fn PublicKey::preferred_aead(self : PublicKey) -> Array[(Int, Int)] {
  match self.self_signature().preferred_aead() {
    Some(list) => if !list.is_empty() { return list }
    None => ()
  }
  match self.direct_signature {
    Some(sig) =>
      match sig.preferred_aead() {
        Some(list) => return list
        None => ()
      }
    None => ()
  }
  []
}

///|
/// True when the key advertises v2 SEIPD support in its Features
/// subpacket (RFC 9580 §5.2.3.32).
pub fn PublicKey::supports_seipd_v2(self : PublicKey) -> Bool {
  if self.self_signature().supports_seipd_v2() {
    return true
  }
  match self.direct_signature {
    Some(sig) => sig.supports_seipd_v2()
    None => false
  }
}

///|
/// Public half to binary packets.
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.PublicKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  match self.direct_signature {
    Some(b) =>
      w.bytes(
        @packet.serialize_packet(@packet.Signature, b.to_body().exact_view()).exact_view(),
      )
    None => ()
  }
  // Emit every certified User ID with its own certification (M5). A
  // bare v6 key emits none here; its Direct Key signature was already
  // written above.
  for binding in self.user_ids {
    let uid = @primitives.utf8_bytes(binding.user_id)
    w.bytes(
      @packet.serialize_packet(@packet.UserId, uid.exact_view()).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(
        @packet.Signature,
        binding.self_signature.to_body().exact_view(),
      ).exact_view(),
    )
  }
  match self.encryption_subkey {
    Some(subkey) => {
      w.bytes(
        @packet.serialize_packet(
          @packet.PublicSubkey,
          subkey.to_body().exact_view(),
        ).exact_view(),
      )
      match self.subkey_binding {
        Some(b) =>
          w.bytes(
            @packet.serialize_packet(
              @packet.Signature,
              b.to_body().exact_view(),
            ).exact_view(),
          )
        None => ()
      }
    }
    None => ()
  }
  w.to_bytes()
}

///|
/// Export as ASCII-armored public key block.
pub fn PublicKey::to_armored(self : PublicKey) -> String {
  @armor.PublicKey.encode(self.to_bytes().exact_view())
}

///|
fn packets_of(data : BytesView) -> Array[@packet.RawPacket] raise {
  @packet.parse_packets(data)
}

///|
fn build_public(packets : Array[@packet.RawPacket]) -> PublicKey raise {
  let mut primary : @packet.PublicKeyPacket? = None
  // User IDs pair with the certification that follows them (wire order;
  // a later certification of the same User ID replaces the earlier one).
  let bindings : Array[UserIdBinding] = []
  let mut pending_uid : String? = None
  let mut direct : @packet.SignaturePacket? = None
  let mut subkey : @packet.PublicKeyPacket? = None
  let mut binding : @packet.SignaturePacket? = None
  let revocations : Array[@packet.SignaturePacket] = []
  let mut subkey_revocation : @packet.SignaturePacket? = None
  for p in packets {
    match p.tag() {
      @packet.PublicKey =>
        primary = Some(@packet.PublicKeyPacket::parse(p.body().exact_view()))
      @packet.SecretKey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        primary = Some(sk.public)
      }
      @packet.UserId =>
        // Lossy on purpose: a key with an undecodable User ID stays usable
        // for its subkeys (gopenpgp keeps raw bytes; we keep a best-effort
        // string instead of failing the whole key).
        pending_uid = Some(@utf8.decode_lossy(p.body().exact_view()))
      @packet.Signature => {
        let s = @packet.SignaturePacket::parse(p.body().exact_view())
        match s.sig_type() {
          @packet.PositiveCertification | @packet.GenericCertification => {
            let uid = match pending_uid {
              Some(u) => u
              // A certification before any User ID cannot be bound to
              // anything; keys are not required to interleave, so treat
              // it as an unbound stray and reject the import (strict).
              None =>
                @error.fail("api: certification without a preceding user id")
            }
            let cert = UserIdBinding::{ user_id: uid, self_signature: s, }
            // Last certification of the same User ID wins.
            let mut replaced = false
            for i in 0..<bindings.length() {
              if bindings[i].user_id == uid {
                bindings[i] = cert
                replaced = true
              }
            }
            if !replaced {
              bindings.push(cert)
            }
          }
          @packet.DirectSignature => direct = Some(s)
          @packet.SubkeyBinding => binding = Some(s)
          @packet.KeyRevocation => revocations.push(s)
          @packet.SubkeyRevocation => subkey_revocation = Some(s)
          // CertificationRevocation withdrawals are not modeled.
          _ => ()
        }
      }
      @packet.PublicSubkey =>
        subkey = Some(@packet.PublicKeyPacket::parse(p.body().exact_view()))
      @packet.SecretSubkey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        subkey = Some(sk.public)
      }
      _ => ()
    }
  }
  match primary {
    Some(p) => {
      // RFC 9580 §5.2.3.10: a v6 key must carry a valid Direct Key
      // signature before it may be used. A v6 key without a User ID uses
      // that signature as its key-level self-signature.
      if p.version() >= 6 && direct is None {
        @error.fail("api: v6 key has no direct-key signature")
      }
      // Only a bare key (no User ID) may rely on its Direct signature
      // alone; every certified User ID must carry a certification.
      if bindings.is_empty() && direct is None {
        @error.fail("api: key has no self-signature")
      }
      validate_key_signatures(p, bindings, direct, subkey, binding)
      PublicKey::{
        primary: p,
        user_ids: bindings,
        direct_signature: direct,
        encryption_subkey: subkey,
        subkey_binding: binding,
        revocations,
        subkey_revocation,
      }
    }
    None => @error.fail("api: no key packet found")
  }
}

///|
/// Import-time cryptographic validation (M1): every signature the key
/// model relies on must verify over the material it certifies. Revocation
/// signatures are excluded — their validity is time-dependent and they
/// are verified lazily by `is_revoked`.
fn validate_key_signatures(
  primary : @packet.PublicKeyPacket,
  bindings : Array[UserIdBinding],
  direct : @packet.SignaturePacket?,
  subkey : @packet.PublicKeyPacket?,
  binding : @packet.SignaturePacket?,
) -> Unit raise {
  for b in bindings {
    let ok = verify_key_signature(
      b.self_signature,
      primary,
      primary,
      user_id=b.user_id,
    ) catch {
      _ => false
    }
    if !ok {
      @error.fail("api: user id self-signature does not verify over the key")
    }
  }
  match direct {
    Some(d) => {
      let ok = verify_key_signature(d, primary, primary, direct=true) catch {
        _ => false
      }
      if !ok {
        @error.fail("api: direct-key signature does not verify over the key")
      }
    }
    None => ()
  }
  match (subkey, binding) {
    (Some(sk), Some(b)) => {
      let ok = verify_key_signature(b, primary, sk) catch { _ => false }
      if !ok {
        @error.fail(
          "api: subkey binding signature does not verify over the key",
        )
      }
    }
    _ => ()
  }
}

///|
/// Parse a transferable public key from binary packets.
pub fn PublicKey::from_bytes(data : BytesView) -> PublicKey raise {
  build_public(packets_of(data))
}

///|
/// Parse a transferable private key from binary packets. The secret
/// material stays in whatever state the wire had it (locked or unlocked);
/// use `PrivateKey::unlock` for locked keys.
pub fn PrivateKey::from_bytes(data : BytesView) -> PrivateKey raise {
  let packets = packets_of(data)
  let pub_half = build_public(packets)
  let mut primary : @packet.SecretKeyPacket? = None
  let mut subkey : @packet.SecretKeyPacket? = None
  let mut binding : @packet.SignaturePacket? = None
  for p in packets {
    match p.tag() {
      @packet.SecretKey =>
        primary = Some(@packet.SecretKeyPacket::parse(p.body().exact_view()))
      @packet.SecretSubkey =>
        subkey = Some(@packet.SecretKeyPacket::parse(p.body().exact_view()))
      @packet.Signature => {
        let s = @packet.SignaturePacket::parse(p.body().exact_view())
        if s.sig_type() == @packet.SubkeyBinding {
          binding = Some(s)
        }
      }
      _ => ()
    }
  }
  match primary {
    Some(p) =>
      PrivateKey::{
        primary: p,
        user_ids: pub_half.user_ids,
        direct_signature: pub_half.direct_signature,
        encryption_subkey: subkey,
        subkey_binding: binding,
        revocations: pub_half.revocations,
        subkey_revocation: pub_half.subkey_revocation,
      }
    None => @error.fail("api: no secret key packet found")
  }
}

///|
/// Parse an armored key block (public or private) into a PrivateKey when
/// it carries secret material.
pub fn PrivateKey::from_armored(text : String) -> PrivateKey raise {
  let block = @armor.decode(text)
  match block.armor_type() {
    @armor.PrivateKey => PrivateKey::from_bytes(block.data().exact_view())
    _ => @error.fail("api: not a private key armor block")
  }
}

///|
/// Parse an armored key block into a public key; a private-key block is
/// accepted and stripped to its public half.
pub fn PublicKey::from_armored(text : String) -> PublicKey raise {
  let block = @armor.decode(text)
  match block.armor_type() {
    @armor.PublicKey => PublicKey::from_bytes(block.data().exact_view())
    @armor.PrivateKey =>
      PrivateKey::from_bytes(block.data().exact_view()).to_public()
    _ => @error.fail("api: not a key armor block")
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

///|
/// Generate a transferable key with an Ed25519 primary (EdDSA legacy,
/// signing/certification) and a Curve25519Legacy ECDH encryption
/// subkey — the gopenpgp "Default" profile shape. EdDSA signatures
/// require the digest itself as the Ed25519 message (RFC 9580 §5.2.3).
pub fn generate_ed25519_key(user_id : String) -> PrivateKey raise {
  let now = @primitives.unix_now().to_int()
  let seed = @primitives.random_bytes(32)
  let primary = build_eddsa_secret_key_packet(seed, now)
  let self_sig = make_self_signature(primary, primary.public, user_id, now)
  let subkey = build_ecdh_secret_key_packet(now)
  let binding = make_binding_signature(
    primary,
    primary.public,
    subkey.public,
    now,
  )
  PrivateKey::{
    primary,
    user_ids: [UserIdBinding::{ user_id, self_signature: self_sig, }],
    direct_signature: None,
    encryption_subkey: Some(subkey),
    subkey_binding: Some(binding),
    revocations: [],
    subkey_revocation: None,
  }
}

///|
/// Build a v6 X25519 encryption secret subkey packet (RFC 9580 §5.5.5.7):
/// the public parameter is the 32-octet native public key and the secret
/// material the 32-octet native secret key, both raw (v6 native
/// algorithms carry no MPI prefix and no checksum).
fn build_v6_x25519_secret_key_packet(
  creation : Int,
) -> @packet.SecretKeyPacket raise {
  let x = @pki.x25519_generate()
  let pub_packet : @packet.PublicKeyPacket = {
    version: 6,
    creation_time: creation,
    algo: @packet.X25519,
    params: [x.public],
  }
  @packet.SecretKeyPacket::{
    public: pub_packet,
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: x.scalar,
    dummy: false,
  }
}

///|
/// Generate a v6 Ed25519 signing key with an X25519 encryption subkey
/// (RFC 9580 §5.5.5.7/§5.5.5.9) — the shape of the Appendix A.3/A.4
/// sample certificate: a v6 primary key with a User ID self-certification,
/// the Direct Key signature the RFC requires before a v6 key may be used,
/// and a v6 X25519 subkey with a v6 binding signature.
pub fn generate_ed25519_v6_key(user_id : String) -> PrivateKey raise {
  let now = @primitives.unix_now().to_int()
  let seed = @primitives.random_bytes(32)
  let primary = build_ed25519_v6_secret_key_packet(seed, now)
  let self_sig = make_self_signature(primary, primary.public, user_id, now)
  let direct = make_direct_key_signature(primary, primary.public, now)
  let subkey = build_v6_x25519_secret_key_packet(now)
  let binding = make_binding_signature(
    primary,
    primary.public,
    subkey.public,
    now,
  )
  PrivateKey::{
    primary,
    user_ids: [UserIdBinding::{ user_id, self_signature: self_sig, }],
    direct_signature: Some(direct),
    encryption_subkey: Some(subkey),
    subkey_binding: Some(binding),
    revocations: [],
    subkey_revocation: None,
  }
}

///|
pub extend PrivateKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PublicKey with @moonbitlang/core/debug.Debug::{to_repr}
