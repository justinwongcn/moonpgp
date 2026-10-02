///|
/// Public key algorithm IDs (RFC 9580 §9.2).
pub(all) enum PubKeyAlgo {
  RsaEncryptOrSign
  RsaEncryptOnly
  RsaSignOnly
  Dsa
  Ecdh
  Ecdsa
  EdDsaLegacy
  X25519
  Ed25519
  Unknown(Int)
} derive(Eq, Debug)

///|
pub fn PubKeyAlgo::number(self : PubKeyAlgo) -> Int {
  match self {
    RsaEncryptOrSign => 1
    RsaEncryptOnly => 2
    RsaSignOnly => 3
    Dsa => 17
    Ecdh => 18
    Ecdsa => 19
    EdDsaLegacy => 22
    X25519 => 25
    Ed25519 => 27
    Unknown(n) => n
  }
}

///|
pub fn pub_key_algo_of_number(n : Int) -> PubKeyAlgo {
  match n {
    1 => RsaEncryptOrSign
    2 => RsaEncryptOnly
    3 => RsaSignOnly
    17 => Dsa
    18 => Ecdh
    19 => Ecdsa
    22 => EdDsaLegacy
    25 => X25519
    27 => Ed25519
    _ => Unknown(n)
  }
}

///|
pub fn PubKeyAlgo::is_rsa(self : PubKeyAlgo) -> Bool {
  match self {
    RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => true
    _ => false
  }
}

///|
/// A version 4 (or 5) public key packet body (RFC 9580 §5.5.2).
pub(all) struct PublicKeyPacket {
  version : Int
  /// Seconds since the Unix epoch.
  creation_time : Int
  algo : PubKeyAlgo
  /// Algorithm-specific public parameters in wire order (MPI bodies for
  /// RSA: n then e).
  params : Array[Bytes]
} derive(Debug)

///|
pub fn PublicKeyPacket::version(self : PublicKeyPacket) -> Int {
  self.version
}

///|
pub fn PublicKeyPacket::creation_time(self : PublicKeyPacket) -> Int {
  self.creation_time
}

///|
pub fn PublicKeyPacket::algo(self : PublicKeyPacket) -> PubKeyAlgo {
  self.algo
}

///|
pub fn PublicKeyPacket::params(self : PublicKeyPacket) -> Array[Bytes] {
  self.params
}

///|
pub fn PublicKeyPacket::parse(body : BytesView) -> PublicKeyPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 4 || version == 5 else {
    raise @error.PgpError::PgpError(
      msg="packet: unsupported public key version \{version}",
    )
  }
  let creation_time = r.read_u32()
  let algo_num = r.read_u8()
  let algo = pub_key_algo_of_number(algo_num)
  let params : Array[Bytes] = []
  match algo {
    RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => {
      params.push(r.read_mpi())
      params.push(r.read_mpi())
    }
    EdDsaLegacy => {
      // First param: the length-prefixed curve OID, kept verbatim
      // (leading octet is the OID length). Second: the MPI point.
      let oid_len = r.read_u8()
      let oid = r.read_bytes(oid_len)
      params.push(Bytes::from_array([oid_len.to_byte()]).add(oid))
      params.push(r.read_mpi())
    }
    Ecdh => {
      // Params in wire order (RFC 9580 §5.5.5.6): length-prefixed curve
      // OID, MPI point, length-prefixed KDF parameters, each kept
      // verbatim.
      let oid_len = r.read_u8()
      let oid = r.read_bytes(oid_len)
      params.push(Bytes::from_array([oid_len.to_byte()]).add(oid))
      params.push(r.read_mpi())
      let kdf_len = r.read_u8()
      let kdf = r.read_bytes(kdf_len)
      params.push(Bytes::from_array([kdf_len.to_byte()]).add(kdf))
    }
    _ =>
      raise @error.PgpError::PgpError(
        msg="packet: unsupported public key algorithm \{algo_num}",
      )
  }
  PublicKeyPacket::{ version, creation_time, algo, params, }
}

///|
pub fn PublicKeyPacket::to_body(self : PublicKeyPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.version)
  w.u32(self.creation_time)
  w.u8(self.algo.number())
  match self.algo {
    EdDsaLegacy => {
      // First param carries the length-prefixed OID verbatim.
      w.bytes(self.params[0].view())
      w.mpi(self.params[1].view())
    }
    Ecdh => {
      // OID and KDF params carry their own length octets; point is an MPI.
      w.bytes(self.params[0].view())
      w.mpi(self.params[1].view())
      w.bytes(self.params[2].view())
    }
    _ =>
      for p in self.params {
        w.mpi(p.view())
      }
  }
  w.to_bytes()
}

///|
/// v4 fingerprint: SHA-1 over 0x99, 2-octet length, key body.
/// Returns 20 octets for v4 keys.
pub fn PublicKeyPacket::fingerprint(self : PublicKeyPacket) -> Bytes raise {
  guard self.version == 4 else {
    raise @error.PgpError::PgpError(
      msg="packet: fingerprint only implemented for v4 keys",
    )
  }
  let body = self.to_body()
  let w = Writer::new()
  w.u8(0x99)
  w.u16(body.length())
  w.bytes(body.view())
  let fp = @primitives.Sha1.digest(w.to_bytes().view())
  fp
}

///|
/// The 8-octet (64-bit) key id derived from the fingerprint.
pub fn PublicKeyPacket::key_id(self : PublicKeyPacket) -> Bytes raise {
  let fp = self.fingerprint()
  fp[fp.length() - 8:fp.length()].to_owned()
}

///|
/// A version 4 secret key packet: public part plus secret material.
/// The secret material is kept in wire form; unlocking/locking happens at
/// the key-management layer.
pub(all) struct SecretKeyPacket {
  public : PublicKeyPacket
  /// S2K usage: 0 = plaintext secret, 254 = CFB + SHA-1 check,
  /// 255 = CFB + 2-octet checksum, other = legacy cipher id + checksum.
  s2k_usage : Int
  /// Cipher algorithm id when the secret material is encrypted (0 otherwise).
  cipher_algo : Int
  /// S2K specifier bytes when encrypted.
  s2k_spec : Bytes
  /// IV bytes when encrypted.
  iv : Bytes
  /// The (possibly still encrypted) algorithm-specific secret material,
  /// exactly as found on the wire after the S2K/IV fields.
  secret_material : Bytes
  /// True for GnuPG "GNU dummy" keys whose secret material lives on a
  /// smartcard (S2K type 101 marker); there is nothing to unlock.
  dummy : Bool
} derive(Debug)

///|
pub fn SecretKeyPacket::parse(body : BytesView) -> SecretKeyPacket raise {
  // The public part length is needed to hash/serialize; parse it first.
  let pub_len = public_part_length(body)
  let public = PublicKeyPacket::parse(body[0:pub_len])
  let r = Reader::new(body[pub_len:body.length()])
  let usage = r.read_u8()
  if usage == 0 {
    SecretKeyPacket::{
      public,
      s2k_usage: 0,
      cipher_algo: 0,
      s2k_spec: Bytes::new(0),
      iv: Bytes::new(0),
      secret_material: r.read_rest(),
      dummy: false,
    }
  } else if usage == 254 || usage == 255 {
    let cipher_algo = r.read_u8()
    // GnuPG dummy marker: cipher 0 and the S2K "GNU" extension
    // (specifier type 101, hash 0, "GNU", sub-type).
    let rest = r.view()
    if cipher_algo == 0 &&
      rest.length() >= 6 &&
      rest[0].to_int() == 101 &&
      rest[2].to_int() == 71 &&
      rest[3].to_int() == 78 &&
      rest[4].to_int() == 85 {
      SecretKeyPacket::{
        public,
        s2k_usage: usage,
        cipher_algo: 0,
        s2k_spec: r.read_rest(),
        iv: Bytes::new(0),
        secret_material: Bytes::new(0),
        dummy: true,
      }
    } else {
      let (s2k, used) = @s2k.parse(r.view())
      ignore(s2k)
      let consumed = r.read_bytes(used)
      let bs = cipher_block_size(cipher_algo)
      let iv = r.read_bytes(bs)
      SecretKeyPacket::{
        public,
        s2k_usage: usage,
        cipher_algo,
        s2k_spec: consumed,
        iv,
        secret_material: r.read_rest(),
        dummy: false,
      }
    }
  } else {
    // Legacy: the usage octet is itself the cipher algorithm id and a
    // simple S2K (MD5) is implied.
    let cipher_algo = usage
    let simple_spec = Bytes::from_array([0, 1])
    let bs = cipher_block_size(cipher_algo)
    let iv = r.read_bytes(bs)
    SecretKeyPacket::{
      public,
      s2k_usage: usage,
      cipher_algo,
      s2k_spec: simple_spec,
      iv,
      secret_material: r.read_rest(),
      dummy: false,
    }
  }
}

///|
/// The length of the public-key part at the front of a secret key body:
/// parse the fields without raising on trailing data.
fn public_part_length(body : BytesView) -> Int raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 4 || version == 5 else {
    raise @error.PgpError::PgpError(
      msg="packet: unsupported public key version \{version}",
    )
  }
  ignore(r.read_u32())
  let algo_num = r.read_u8()
  let algo = pub_key_algo_of_number(algo_num)
  match algo {
    RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => {
      let n = r.read_mpi()
      ignore(n)
      let e = r.read_mpi()
      ignore(e)
    }
    EdDsaLegacy => {
      let oid_len = r.read_u8()
      ignore(r.read_bytes(oid_len))
      ignore(r.read_mpi())
    }
    Ecdh => {
      let oid_len = r.read_u8()
      ignore(r.read_bytes(oid_len))
      ignore(r.read_mpi())
      let kdf_len = r.read_u8()
      ignore(r.read_bytes(kdf_len))
    }
    _ =>
      raise @error.PgpError::PgpError(
        msg="packet: unsupported public key algorithm \{algo_num}",
      )
  }
  r.position()
}

///|
/// Block size of a symmetric algorithm id (only what v4 key protection
/// needs). Returns 16 for unknown ids of the AES family and 8 for legacy
/// 64-bit ciphers.
fn cipher_block_size(algo : Int) -> Int raise {
  match algo {
    1 => 8
    2 | 3 | 4 => 8
    7 | 8 | 9 | 10 | 11 | 12 => 16
    _ =>
      raise @error.PgpError::PgpError(
        msg="packet: unknown cipher algorithm \{algo}",
      )
  }
}

///|
/// Serialize: public body followed by the secret-material wire bytes.
pub fn SecretKeyPacket::to_body(self : SecretKeyPacket) -> Bytes {
  let w = Writer::new()
  w.bytes(self.public.to_body().view())
  w.u8(self.s2k_usage)
  if self.s2k_usage == 0 {
    w.bytes(self.secret_material.view())
  } else if self.s2k_usage == 254 || self.s2k_usage == 255 {
    w.u8(self.cipher_algo)
    w.bytes(self.s2k_spec.view())
    w.bytes(self.iv.view())
    w.bytes(self.secret_material.view())
  } else {
    // Legacy usage octet is the cipher id; IV follows, simple S2K implied.
    w.u8(self.cipher_algo)
    w.bytes(self.iv.view())
    w.bytes(self.secret_material.view())
  }
  w.to_bytes()
}
