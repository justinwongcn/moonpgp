///|
fn build_eddsa_secret_key_packet(
  seed : Bytes,
  creation : Int32,
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
  creation : Int32,
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
  creation : Int32,
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
/// Generate a fresh transferable key: RSA primary (certify+sign) with a
/// User ID self-certification plus an RSA encryption subkey.
pub fn generate_key(user_id : String, bits~ : Int32 = 3072) -> PrivateKey raise {
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
  creation : Int32,
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
