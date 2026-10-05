///|
/// An OpenPGP transferable private key: v4 RSA primary key, one User ID
/// with its self-certification, and an RSA encryption subkey with its
/// binding signature.
pub(all) struct PrivateKey {
  primary : @packet.SecretKeyPacket
  user_id : String
  self_signature : @packet.SignaturePacket
  encryption_subkey : @packet.SecretKeyPacket?
  subkey_binding : @packet.SignaturePacket?
} derive(Debug)

///|
/// The public half of a transferable key.
pub(all) struct PublicKey {
  primary : @packet.PublicKeyPacket
  user_id : String
  self_signature : @packet.SignaturePacket
  encryption_subkey : @packet.PublicKeyPacket?
  subkey_binding : @packet.SignaturePacket?
} derive(Debug)

///|
pub fn PrivateKey::key_id(self : PrivateKey) -> Bytes raise {
  self.primary.public.key_id()
}

///|
pub fn PrivateKey::fingerprint(self : PrivateKey) -> Bytes raise {
  self.primary.public.fingerprint()
}

///|
pub fn PrivateKey::user_id(self : PrivateKey) -> String {
  self.user_id
}

///|
pub fn PublicKey::key_id(self : PublicKey) -> Bytes raise {
  self.primary.key_id()
}

///|
pub fn PublicKey::fingerprint(self : PublicKey) -> Bytes raise {
  self.primary.fingerprint()
}

///|
pub fn PublicKey::user_id(self : PublicKey) -> String {
  self.user_id
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
    user_id: self.user_id,
    self_signature: self.self_signature,
    encryption_subkey: match self.encryption_subkey {
      Some(sk) => Some(sk.public)
      None => None
    },
    subkey_binding: self.subkey_binding,
  }
}

///|
/// RSA MPI helpers: extract n/e/d/p/q/u as BigInts.
fn rsa_public_parts(p : @packet.PublicKeyPacket) -> (BigInt, BigInt) raise {
  let params = p.params()
  guard params.length() == 2 else {
    raise @error.PgpError::PgpError(msg="api: bad RSA public parameters")
  }
  (
    BigInt::from_octets(params[0].exact_view(), signum=1),
    BigInt::from_octets(params[1].exact_view(), signum=1),
  )
}

///|
fn rsa_secret_parts(p : @packet.SecretKeyPacket) -> @pki.RsaPrivateKey raise {
  guard p.s2k_usage == 0 else {
    raise @error.PgpError::PgpError(
      msg="api: secret key material is locked; unlock it first",
    )
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
    raise @error.PgpError::PgpError(
      msg="api: secret key material is locked; unlock it first",
    )
  }
  let r = @packet.Reader::new(p.secret_material.exact_view())
  // MPI strips leading zero octets; a seed whose first octet is 0x00
  // (probability 1/256) arrives as 31 bytes. Pad back to the fixed
  // 32-octet scalar on read.
  let seed_mpi = r.read_mpi()
  guard seed_mpi.length() <= 32 else {
    raise @error.PgpError::PgpError(msg="api: bad EdDSA seed length")
  }
  let seed = @primitives.pad_left(seed_mpi.exact_view(), 32)
  let point = p.public.params()[1]
  guard point.length() == 33 else {
    raise @error.PgpError::PgpError(msg="api: bad EdDSA point")
  }
  @pki.Ed25519SecretKey::{ seed, public: point[1:point.length()].to_owned(), }
}

///|
/// Sign `digest` with the key's algorithm; returns the algorithm-specific
/// signature MPI bodies (RSA: DigestInfo-encoded EM; EdDSA: r and s).
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
    _ => {
      let rsa = rsa_secret_parts(secret_packet)
      [rsa.pkcs1_v15_sign(hash, digest)]
    }
  }
}

///|
/// Verify algorithm-specific signature material against a public key packet.
pub fn verify_sig_material(
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
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: w2.to_bytes(),
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
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: w2.to_bytes(),
    dummy: false,
  }
}

///|
/// Preferred algorithm subpackets used in our self-signatures.
fn preferred_subpackets() -> Array[@packet.SigSubpacket] {
  [
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
      body: Bytes::from_array([1]),
    },
  ]
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
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x03),
    ..preferred_subpackets(),
  ]
  let issuer : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
      body: pub_packet.key_id(),
    },
  ]
  let sig : @packet.SignaturePacket = {
    sig_type: @packet.PositiveCertification,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: issuer,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    sig_params: [],
  }
  let digest = hash_certification(sig, pub_packet, user_id)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Create a subkey binding signature (0x18).
fn make_binding_signature(
  secret_packet : @packet.SecretKeyPacket,
  primary_pub : @packet.PublicKeyPacket,
  subkey_pub : @packet.PublicKeyPacket,
  now : Int,
) -> @packet.SignaturePacket raise {
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x0C),
    ..preferred_subpackets(),
  ]
  let issuer : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
      body: primary_pub.key_id(),
    },
  ]
  let sig : @packet.SignaturePacket = {
    sig_type: @packet.SubkeyBinding,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: issuer,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    sig_params: [],
  }
  let digest = hash_binding(sig, primary_pub, subkey_pub)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Hash data for a User ID certification.
fn hash_certification(
  sig : @packet.SignaturePacket,
  pub_packet : @packet.PublicKeyPacket,
  user_id : String,
) -> Bytes raise {
  let key_body = pub_packet.to_body()
  let uid = @primitives.utf8_bytes(user_id)
  let w = @packet.Writer::new()
  w.u8(0x99)
  w.u16(key_body.length())
  w.bytes(key_body.exact_view())
  w.u8(0xB4)
  w.u32(uid.length())
  w.bytes(uid.exact_view())
  w.bytes(sig.hash_prefix().exact_view())
  w.bytes(@packet.signature_trailer(sig.hash_prefix().length()).exact_view())
  signature_digest(sig, w.to_bytes().exact_view())
}

///|
/// Digest `data` under the signature packet's hash algorithm.
fn signature_digest(
  sig : @packet.SignaturePacket,
  data : BytesView,
) -> Bytes raise {
  match @primitives.hash_id_of_number(sig.hash_algo()) {
    Some(h) => h.digest(data)
    None =>
      raise @error.PgpError::PgpError(
        msg="api: unsupported signature hash algorithm \{sig.hash_algo()}",
      )
  }
}

///|
/// Hash data for a subkey binding signature.
fn hash_binding(
  sig : @packet.SignaturePacket,
  primary_pub : @packet.PublicKeyPacket,
  subkey_pub : @packet.PublicKeyPacket,
) -> Bytes raise {
  let primary_body = primary_pub.to_body()
  let subkey_body = subkey_pub.to_body()
  let w = @packet.Writer::new()
  w.u8(0x99)
  w.u16(primary_body.length())
  w.bytes(primary_body.exact_view())
  w.u8(0x99)
  w.u16(subkey_body.length())
  w.bytes(subkey_body.exact_view())
  w.bytes(sig.hash_prefix().exact_view())
  w.bytes(@packet.signature_trailer(sig.hash_prefix().length()).exact_view())
  signature_digest(sig, w.to_bytes().exact_view())
}

///|
/// Verify a self-certification or binding signature over key material.
pub fn verify_key_signature(
  sig : @packet.SignaturePacket,
  signer_pub : @packet.PublicKeyPacket,
  certified_pub : @packet.PublicKeyPacket,
  user_id? : String,
) -> Bool raise {
  let digest : Bytes = match user_id {
    Some(uid) => hash_certification(sig, certified_pub, uid)
    None => hash_binding(sig, signer_pub, certified_pub)
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
    user_id,
    self_signature: self_sig,
    encryption_subkey: Some(subkey),
    subkey_binding: Some(binding),
  }
}

///|
/// Serialize to binary packets: SecretKey || UserID || cert || [
/// SecretSubkey || binding ].
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  let uid = @primitives.utf8_bytes(self.user_id)
  w.bytes(
    @packet.serialize_packet(@packet.UserId, uid.exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Signature,
      self.self_signature.to_body().exact_view(),
    ).exact_view(),
  )
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
/// Public half to binary packets.
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.PublicKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  let uid = @primitives.utf8_bytes(self.user_id)
  w.bytes(
    @packet.serialize_packet(@packet.UserId, uid.exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Signature,
      self.self_signature.to_body().exact_view(),
    ).exact_view(),
  )
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
  let mut user_id = ""
  let mut self_sig : @packet.SignaturePacket? = None
  let mut subkey : @packet.PublicKeyPacket? = None
  let mut binding : @packet.SignaturePacket? = None
  for p in packets {
    match p.tag() {
      @packet.PublicKey =>
        primary = Some(@packet.PublicKeyPacket::parse(p.body().exact_view()))
      @packet.SecretKey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        primary = Some(sk.public)
      }
      @packet.UserId =>
        user_id = @utf8.decode(p.body().exact_view()) catch { _ => "" }
      @packet.Signature => {
        let s = @packet.SignaturePacket::parse(p.body().exact_view())
        match s.sig_type() {
          @packet.PositiveCertification | @packet.GenericCertification =>
            self_sig = Some(s)
          @packet.SubkeyBinding => binding = Some(s)
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
    Some(p) =>
      PublicKey::{
        primary: p,
        user_id,
        self_signature: match self_sig {
          Some(s) => s
          None =>
            raise @error.PgpError::PgpError(
              msg="api: key has no self-signature",
            )
        },
        encryption_subkey: subkey,
        subkey_binding: binding,
      }
    None => raise @error.PgpError::PgpError(msg="api: no key packet found")
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
        user_id: pub_half.user_id,
        self_signature: pub_half.self_signature,
        encryption_subkey: subkey,
        subkey_binding: binding,
      }
    None =>
      raise @error.PgpError::PgpError(msg="api: no secret key packet found")
  }
}

///|
/// Parse an armored key block (public or private) into a PrivateKey when
/// it carries secret material.
pub fn PrivateKey::from_armored(text : String) -> PrivateKey raise {
  let block = @armor.decode(text)
  match block.armor_type() {
    @armor.PrivateKey => PrivateKey::from_bytes(block.data().exact_view())
    _ =>
      raise @error.PgpError::PgpError(msg="api: not a private key armor block")
  }
}

///|
pub fn PublicKey::from_armored(text : String) -> PublicKey raise {
  let block = @armor.decode(text)
  match block.armor_type() {
    @armor.PublicKey => PublicKey::from_bytes(block.data().exact_view())
    @armor.PrivateKey =>
      PrivateKey::from_bytes(block.data().exact_view()).to_public()
    _ => raise @error.PgpError::PgpError(msg="api: not a key armor block")
  }
}

///|
/// RSA public key view of a public key packet.
pub fn rsa_public_key(
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
    user_id,
    self_signature: self_sig,
    encryption_subkey: Some(subkey),
    subkey_binding: Some(binding),
  }
}

///|
pub extend PrivateKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PublicKey with @moonbitlang/core/debug.Debug::{to_repr}
