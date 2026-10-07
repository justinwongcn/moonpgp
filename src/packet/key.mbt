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
/// Parse the version/creation-time/algorithm/params fields at the front of
/// a public key body (F13: the single source of the field walk, shared by
/// `PublicKeyPacket::parse` and `public_part_length` so the two cannot
/// drift apart when an algorithm is added or changed).
fn read_public_fields(r : Reader) -> (Int, Int, PubKeyAlgo, Array[Bytes]) raise {
  let version = r.read_u8()
  guard version == 4 || version == 5 || version == 6 else {
    @error.fail("packet: unsupported public key version \{version}")
  }
  let creation_time = r.read_u32()
  let algo_num = r.read_u8()
  let algo = pub_key_algo_of_number(algo_num)
  let params : Array[Bytes] = []
  if version == 6 {
    // Version 6 carries a 4-octet count of the algorithm-specific
    // material (RFC 9580 §5.5.2.3); native algorithms are raw octet
    // strings, not MPIs.
    let count = r.read_u32()
    let material_start = r.position()
    match algo {
      RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => {
        params.push(r.read_mpi())
        params.push(r.read_mpi())
      }
      Ed25519 =>
        // 32 octets of the native Ed25519 public key (RFC 9580 §5.5.5.9).
        params.push(r.read_bytes(32))
      X25519 =>
        // 32 octets of the native X25519 public key (RFC 9580 §5.5.5.7).
        params.push(r.read_bytes(32))
      _ =>
        @error.fail("packet: v6 public key algorithm \{algo_num} not supported")
    }
    guard r.position() - material_start == count else {
      @error.fail("packet: v6 public key material count does not match body")
    }
  } else {
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
      _ => @error.fail("packet: unsupported public key algorithm \{algo_num}")
    }
  }
  (version, creation_time, algo, params)
}

///|
pub fn PublicKeyPacket::parse(body : BytesView) -> PublicKeyPacket raise {
  let r = Reader::new(body)
  let (version, creation_time, algo, params) = read_public_fields(r)
  PublicKeyPacket::{ version, creation_time, algo, params, }
}

///|
pub fn PublicKeyPacket::to_body(self : PublicKeyPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.version)
  w.u32(self.creation_time)
  w.u8(self.algo.number())
  if self.version >= 6 {
    // 4-octet count of the algorithm-specific material, then the raw
    // (native) or MPI-encoded fields.
    let material = Writer::new()
    match self.algo {
      Ed25519 | X25519 =>
        for p in self.params {
          material.bytes(p.exact_view())
        }
      _ =>
        for p in self.params {
          material.mpi(p.exact_view())
        }
    }
    let mb = material.to_bytes()
    w.u32(mb.length())
    w.bytes(mb.exact_view())
  } else {
    match self.algo {
      EdDsaLegacy => {
        // First param carries the length-prefixed OID verbatim.
        w.bytes(self.params[0].exact_view())
        w.mpi(self.params[1].exact_view())
      }
      Ecdh => {
        // OID and KDF params carry their own length octets; point is an MPI.
        w.bytes(self.params[0].exact_view())
        w.mpi(self.params[1].exact_view())
        w.bytes(self.params[2].exact_view())
      }
      _ =>
        for p in self.params {
          w.mpi(p.exact_view())
        }
    }
  }
  w.to_bytes()
}

///|
/// Fingerprint: v4 = SHA-1 over 0x99, 2-octet length, key body (20
/// octets); v6 = SHA-256 over 0x9B, 4-octet length, key body (32 octets)
/// (RFC 9580 §5.5.4.3).
pub fn PublicKeyPacket::fingerprint(self : PublicKeyPacket) -> Bytes raise {
  let body = self.to_body()
  let w = Writer::new()
  if self.version >= 6 {
    w.u8(0x9B)
    w.u32(body.length())
    w.bytes(body.exact_view())
    @primitives.Sha256.digest(w.to_bytes().exact_view())
  } else if self.version == 4 {
    // F09: the u16 length field silently truncates an oversized body.
    guard body.length() <= 0xFFFF else {
      @error.fail("packet: key packet too large for a v4 fingerprint")
    }
    w.u8(0x99)
    w.u16(body.length())
    w.bytes(body.exact_view())
    @primitives.Sha1.digest(w.to_bytes().exact_view())
  } else {
    @error.fail(
      "packet: fingerprint not implemented for version \{self.version}",
    )
  }
}

///|
/// The 8-octet (64-bit) key id derived from the fingerprint: the low 64
/// bits for v4, the HIGH 64 bits for v6 (RFC 9580 §5.5.4.3).
pub fn PublicKeyPacket::key_id(self : PublicKeyPacket) -> Bytes raise {
  let fp = self.fingerprint()
  if self.version >= 6 {
    fp[0:8].to_owned()
  } else {
    fp[fp.length() - 8:fp.length()].to_owned()
  }
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
  let v6 = public.version() >= 6
  let r = Reader::new(body[pub_len:body.length()])
  let usage = r.read_u8()
  if usage == 0 {
    // v6 carries no trailing 2-octet checksum; the material is raw.
    SecretKeyPacket::{
      public,
      s2k_usage: 0,
      cipher_algo: 0,
      s2k_spec: Bytes::new(0),
      iv: Bytes::new(0),
      secret_material: r.read_rest(),
      dummy: false,
    }
  } else if usage == 253 {
    // RFC 9580: AEAD-protected secret key material (OCB by default).
    @error.fail(
      "packet: AEAD-protected secret key material (S2K usage 253) is not supported yet",
    )
  } else if usage == 254 || usage == 255 {
    guard !(v6 && usage == 255) else {
      @error.fail("packet: a v6 secret key must not use S2K usage 255")
    }
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
    } else if v6 {
      // v6 encrypted packets carry a 1-octet count of the following S2K
      // parameter fields (RFC 9580 §5.5.3).
      let declared = r.read_u8()
      guard rest_after(r, declared) else {
        @error.fail("packet: truncated v6 S2K specifier")
      }
      let (s2k, used) = @s2k.parse(r.view()[0:declared])
      ignore(s2k)
      guard used == declared else {
        @error.fail("packet: v6 S2K specifier length mismatch")
      }
      let spec = r.read_bytes(declared)
      let bs = cipher_block_size(cipher_algo)
      let iv = r.read_bytes(bs)
      SecretKeyPacket::{
        public,
        s2k_usage: usage,
        cipher_algo,
        s2k_spec: spec,
        iv,
        secret_material: r.read_rest(),
        dummy: false,
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
/// True when at least `n` bytes remain in the reader.
fn rest_after(r : Reader, n : Int) -> Bool {
  r.view().length() >= n
}

///|
/// The length of the public-key part at the front of a secret key body:
/// walk it with the shared field reader (no trailing-data requirement).
fn public_part_length(body : BytesView) -> Int raise {
  let r = Reader::new(body)
  let _fields = read_public_fields(r)
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
    _ => @error.fail("packet: unknown cipher algorithm \{algo}")
  }
}

///|
/// Serialize: public body followed by the secret-material wire bytes.
pub fn SecretKeyPacket::to_body(self : SecretKeyPacket) -> Bytes {
  let w = Writer::new()
  w.bytes(self.public.to_body().exact_view())
  w.u8(self.s2k_usage)
  if self.s2k_usage == 0 {
    w.bytes(self.secret_material.exact_view())
  } else if self.s2k_usage == 254 || self.s2k_usage == 255 {
    w.u8(self.cipher_algo)
    if self.public.version() >= 6 {
      // v6: 1-octet count of the S2K parameter fields.
      w.u8(self.s2k_spec.length())
    }
    w.bytes(self.s2k_spec.exact_view())
    w.bytes(self.iv.exact_view())
    w.bytes(self.secret_material.exact_view())
  } else {
    // Legacy usage octet is the cipher id; IV follows, simple S2K implied.
    w.u8(self.cipher_algo)
    w.bytes(self.iv.exact_view())
    w.bytes(self.secret_material.exact_view())
  }
  w.to_bytes()
}

///|
pub extend PubKeyAlgo with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PubKeyAlgo with Eq::{not_equal, equal}

///|
pub extend PublicKeyPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SecretKeyPacket with @moonbitlang/core/debug.Debug::{to_repr}
