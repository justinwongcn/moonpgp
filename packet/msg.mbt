///|
/// PKESK packet body, versions 3 (RFC 9580 §5.1.1) and 6 (§5.1.2).
pub(all) struct PkeskPacket {
  version : Int32
  /// v3 only: recipient key id (all zero for a hidden recipient).
  key_id : Bytes
  /// v6 only: recipient key version (0 for an anonymous recipient).
  key_version : Int32
  /// v6 only: recipient fingerprint (empty for an anonymous recipient).
  fingerprint : Bytes
  pub_algo : PubKeyAlgo
  /// RSA: the encrypted session key MPI value. X25519/ECDH: the
  /// key-wrapped session key (§5.1.5/§5.1.6), serialized after
  /// `ecdh_ephemeral`.
  encrypted : Bytes
  /// X25519 only: the 32-octet native ephemeral public key. ECDH only:
  /// the MPI value of the ephemeral point (0x40 || X). Empty for RSA.
  ecdh_ephemeral : Bytes
} derive(Debug)

///|
pub fn PkeskPacket::version(self : PkeskPacket) -> Int32 {
  self.version
}

///|
pub fn PkeskPacket::key_id(self : PkeskPacket) -> Bytes {
  self.key_id
}

///|
pub fn PkeskPacket::key_version(self : PkeskPacket) -> Int32 {
  self.key_version
}

///|
pub fn PkeskPacket::fingerprint(self : PkeskPacket) -> Bytes {
  self.fingerprint
}

///|
pub fn PkeskPacket::pub_algo(self : PkeskPacket) -> PubKeyAlgo {
  self.pub_algo
}

///|
pub fn PkeskPacket::encrypted(self : PkeskPacket) -> Bytes {
  self.encrypted
}

///|
pub fn PkeskPacket::ecdh_ephemeral(self : PkeskPacket) -> Bytes {
  self.ecdh_ephemeral
}

///|
pub fn PkeskPacket::parse(body : BytesView) -> PkeskPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 3 || version == 6 else {
    @error.fail("packet: unsupported PKESK version \{version}")
  }
  let mut key_id = Bytes::new(0)
  let mut key_version = 0
  let mut fingerprint = Bytes::new(0)
  if version == 6 {
    // §5.1.2: a 1-octet size covering the key-version and fingerprint
    // fields; zero means an anonymous recipient and both are absent. The
    // fingerprint length follows from the key version (20 octets for a v4
    // key, 32 for v5/v6), so any other size is malformed: a size of 1 used
    // to be accepted and then re-serialized as 0, silently dropping the
    // key version on an import/export round trip.
    let size = r.read_u8()
    if size > 0 {
      key_version = r.read_u8()
      let fp_len = match key_version {
        4 => 20
        5 | 6 => 32
        _ => 0
      }
      guard fp_len > 0 && size == 1 + fp_len else {
        @error.fail(
          "packet: v6 PKESK size \{size} does not match key version \{key_version}",
        )
      }
      fingerprint = r.read_bytes(size - 1)
    }
  } else {
    key_id = r.read_bytes(8)
  }
  let algo = pub_key_algo_of_number(r.read_u8())
  match algo {
    X25519 => {
      let eph = r.read_bytes(32)
      let size = r.read_u8()
      let wrapped = r.read_bytes(size)
      PkeskPacket::{
        version,
        key_id,
        key_version,
        fingerprint,
        pub_algo: algo,
        encrypted: wrapped,
        ecdh_ephemeral: eph,
      }
    }
    Ecdh => {
      let eph = r.read_mpi()
      let size = r.read_u8()
      let wrapped = r.read_bytes(size)
      PkeskPacket::{
        version,
        key_id,
        key_version,
        fingerprint,
        pub_algo: algo,
        encrypted: wrapped,
        ecdh_ephemeral: eph,
      }
    }
    _ => {
      let encrypted = if algo.is_rsa() { r.read_mpi() } else { r.read_rest() }
      PkeskPacket::{
        version,
        key_id,
        key_version,
        fingerprint,
        pub_algo: algo,
        encrypted,
        ecdh_ephemeral: Bytes::new(0),
      }
    }
  }
}

///|
pub fn PkeskPacket::to_body(self : PkeskPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.version)
  if self.version == 6 {
    if self.fingerprint.length() == 0 {
      w.u8(0)
    } else {
      w.u8(1 + self.fingerprint.length())
      w.u8(self.key_version)
      w.bytes(self.fingerprint.exact_view())
    }
  } else {
    w.bytes(self.key_id.exact_view())
  }
  w.u8(self.pub_algo.number())
  match self.pub_algo {
    X25519 => {
      w.bytes(self.ecdh_ephemeral.exact_view())
      w.u8(self.encrypted.length())
      w.bytes(self.encrypted.exact_view())
    }
    Ecdh => {
      w.mpi(self.ecdh_ephemeral.exact_view())
      w.u8(self.encrypted.length())
      w.bytes(self.encrypted.exact_view())
    }
    _ =>
      if self.pub_algo.is_rsa() {
        w.mpi(self.encrypted.exact_view())
      } else {
        w.bytes(self.encrypted.exact_view())
      }
  }
  w.to_bytes()
}

///|
/// SKESK packet body, versions 4 (RFC 9580 §5.3.1), 5 (the 4880bis /
/// crypto-refresh AEAD-wrapped session key GnuPG 2.4 emits under
/// --force-aead) and 6 (§5.3.2). Version 5 adds the AEAD algorithm and a
/// nonce and seals the session key with the S2K-derived key directly;
/// version 6 adds the two count octets and the HKDF-SHA256 key
/// separation (`info`/AD = tag | version | cipher | aead).
pub(all) struct SkeskPacket {
  version : Int32
  /// Symmetric algorithm used for the message; also the default derivation
  /// length selector for the S2K key.
  cipher_algo : Int32
  /// AEAD algorithm id for version 5 (0 for version 4).
  aead_algo : Int32
  s2k : @s2k.S2k
  /// AEAD IV for version 5 (empty for version 4).
  iv : Bytes
  /// Encrypted session key (v4: algo octet + key, CFB-wrapped; v5: the
  /// AEAD seal of the key alone), present when the S2K key only wraps the
  /// session key. Empty when the S2K derives it directly.
  encrypted_session_key : Bytes
} derive(Debug)

///|
pub fn SkeskPacket::version(self : SkeskPacket) -> Int32 {
  self.version
}

///|
pub fn SkeskPacket::cipher_algo(self : SkeskPacket) -> Int32 {
  self.cipher_algo
}

///|
pub fn SkeskPacket::aead_algo(self : SkeskPacket) -> Int32 {
  self.aead_algo
}

///|
pub fn SkeskPacket::s2k(self : SkeskPacket) -> @s2k.S2k {
  self.s2k
}

///|
pub fn SkeskPacket::iv(self : SkeskPacket) -> Bytes {
  self.iv
}

///|
pub fn SkeskPacket::encrypted_session_key(self : SkeskPacket) -> Bytes {
  self.encrypted_session_key
}

///|
/// IV length of an AEAD algorithm id (RFC 9580 §9.6): 1 EAX=16, 2 OCB=15,
/// 3 GCM=12. Local table (mirroring @cipher.AeadMode::iv_length) keeps the
/// packet layer free of a cipher-package dependency, like the cipher
/// block-size table above.
fn aead_iv_len(algo : Int32) -> Int32 raise {
  match algo {
    1 => 16
    2 => 15
    3 => 12
    _ => @error.fail("packet: unknown AEAD algorithm \{algo}")
  }
}

///|
pub fn SkeskPacket::parse(body : BytesView) -> SkeskPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 4 || version == 5 || version == 6 else {
    @error.fail("packet: unsupported SKESK version \{version}")
  }
  // §5.3.2: a v6 packet opens with a 1-octet count of the cipher, AEAD
  // mode, S2K-length, specifier and nonce fields.
  let v6_params_len = if version == 6 {
    let n = r.read_u8()
    guard rest_after(r, n) else {
      @error.fail("packet: truncated v6 SKESK parameters")
    }
    n
  } else {
    0
  }
  let cipher_algo = r.read_u8()
  let aead_algo = if version == 5 || version == 6 { r.read_u8() } else { 0 }
  let (s2k, spec_len) = if version == 6 {
    let declared = r.read_u8()
    guard rest_after(r, declared) else {
      @error.fail("packet: truncated v6 SKESK S2K specifier")
    }
    let (s2k, used) = @s2k.parse(r.view()[0:declared])
    guard used == declared else {
      @error.fail("packet: v6 SKESK S2K specifier length mismatch")
    }
    ignore(r.read_bytes(declared))
    (s2k, declared)
  } else {
    let (s2k, used) = @s2k.parse(r.view())
    ignore(r.read_bytes(used))
    (s2k, used)
  }
  let iv = if version == 5 || version == 6 {
    r.read_bytes(aead_iv_len(aead_algo))
  } else {
    Bytes::new(0)
  }
  if version == 6 {
    guard v6_params_len == 3 + spec_len + iv.length() else {
      @error.fail("packet: v6 SKESK parameter count mismatch")
    }
  }
  let esk = r.read_rest()
  SkeskPacket::{
    version,
    cipher_algo,
    aead_algo,
    s2k,
    iv,
    encrypted_session_key: esk,
  }
}

///|
pub fn SkeskPacket::to_body(self : SkeskPacket) -> Bytes raise {
  let w = Writer::new()
  w.u8(self.version)
  let spec = self.s2k.encode()
  if self.version != 4 {
    guard self.iv.length() == aead_iv_len(self.aead_algo) else {
      @error.fail("packet: bad SKESK IV length")
    }
  }
  if self.version == 6 {
    w.u8(3 + spec.length() + self.iv.length())
  }
  w.u8(self.cipher_algo)
  if self.version == 5 || self.version == 6 {
    w.u8(self.aead_algo)
  }
  if self.version == 6 {
    w.u8(spec.length())
  }
  w.bytes(spec.exact_view())
  if self.version == 5 || self.version == 6 {
    w.bytes(self.iv.exact_view())
  }
  w.bytes(self.encrypted_session_key.exact_view())
  w.to_bytes()
}

///|
/// AEAD Encrypted Data Packet (tag 20) body, version 1
/// (draft-ietf-openpgp-rfc4880bis §5.16) — the shape GnuPG 2.4 produces
/// under --force-aead. RFC 9580 reserves tag 20 in favour of SEIPD v2;
/// this packet exists here for GnuPG interop and legacy data.
pub(all) struct AeadPacket {
  version : Int32
  cipher_algo : Int32
  aead_algo : Int32
  chunk_octet : Int32
  iv : Bytes
  /// Chunk ciphertexts+tags followed by the final tag.
  ciphertext : Bytes
} derive(Debug)

///|
pub fn AeadPacket::version(self : AeadPacket) -> Int32 {
  self.version
}

///|
pub fn AeadPacket::cipher_algo(self : AeadPacket) -> Int32 {
  self.cipher_algo
}

///|
pub fn AeadPacket::aead_algo(self : AeadPacket) -> Int32 {
  self.aead_algo
}

///|
pub fn AeadPacket::chunk_octet(self : AeadPacket) -> Int32 {
  self.chunk_octet
}

///|
pub fn AeadPacket::iv(self : AeadPacket) -> Bytes {
  self.iv
}

///|
pub fn AeadPacket::ciphertext(self : AeadPacket) -> Bytes {
  self.ciphertext
}

///|
pub fn AeadPacket::parse(body : BytesView) -> AeadPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 1 else {
    @error.fail("packet: unsupported AEAD packet version \{version}")
  }
  let cipher_algo = r.read_u8()
  let aead_algo = r.read_u8()
  let chunk_octet = r.read_u8()
  let iv = r.read_bytes(aead_iv_len(aead_algo))
  let ct = r.read_rest()
  AeadPacket::{
    version,
    cipher_algo,
    aead_algo,
    chunk_octet,
    iv,
    ciphertext: ct,
  }
}

///|
pub fn AeadPacket::to_body(self : AeadPacket) -> Bytes raise {
  guard self.version == 1 else {
    @error.fail("packet: unsupported AEAD packet version \{self.version}")
  }
  guard self.iv.length() == aead_iv_len(self.aead_algo) else {
    @error.fail("packet: bad AEAD packet IV length")
  }
  let w = Writer::new()
  w.u8(self.version)
  w.u8(self.cipher_algo)
  w.u8(self.aead_algo)
  w.u8(self.chunk_octet)
  w.bytes(self.iv.exact_view())
  w.bytes(self.ciphertext.exact_view())
  w.to_bytes()
}

///|
/// Literal data packet body (RFC 9580 §5.9).
pub struct LiteralPacket {
  /// 'b' binary, 'u' UTF-8 text (or legacy 't', reported as 'u').
  format : Char
  file_name : String
  /// Modification date, seconds since epoch.
  date : Int32
  data : Bytes
} derive(Debug)

///|
pub fn LiteralPacket::format(self : LiteralPacket) -> Char {
  self.format
}

///|
pub fn LiteralPacket::file_name(self : LiteralPacket) -> String {
  self.file_name
}

///|
pub fn LiteralPacket::date(self : LiteralPacket) -> Int32 {
  self.date
}

///|
pub fn LiteralPacket::data(self : LiteralPacket) -> Bytes {
  self.data
}

///|
pub fn LiteralPacket::parse(body : BytesView) -> LiteralPacket raise {
  let r = Reader::new(body)
  let fmt = r.read_u8()
  let name_len = r.read_u8()
  let name_bytes = r.read_bytes(name_len)
  let date = r.read_u32()
  let data = r.read_rest()
  let format : Char = match fmt {
    0x62 => 'b'
    0x75 => 'u'
    0x74 => 'u'
    0x6c => 'b'
    _ => 'b'
  }
  // Lossy on purpose (S10): the file name is attacker-controlled wire
  // data; invalid UTF-8 becomes U+FFFD rather than a silent "" that
  // would quietly drop the name on import/export round-trips.
  let name : String = @utf8.decode_lossy(name_bytes.exact_view())
  LiteralPacket::{ format, file_name: name, date, data, }
}

///|
pub fn LiteralPacket::to_body(self : LiteralPacket) -> Bytes raise {
  let w = Writer::new()
  w.u8(
    match self.format {
      'u' => 0x75
      _ => 0x62
    },
  )
  let name = @primitives.utf8_bytes(self.file_name)
  guard name.length() <= 255 else {
    @error.fail("packet: literal file name too long")
  }
  w.u8(name.length())
  w.bytes(name.exact_view())
  w.u32(self.date)
  w.bytes(self.data.exact_view())
  w.to_bytes()
}

///|
/// Build a literal packet around raw data (text uses format 'b' to avoid
/// any newline conversion unless the caller explicitly wants 'u').
pub fn LiteralPacket::binary(
  data : BytesView,
  file_name? : String,
) -> LiteralPacket {
  LiteralPacket::{
    format: 'b',
    file_name: match file_name {
      Some(n) => n
      None => ""
    },
    date: 0,
    data: data.to_owned(),
  }
}

///|
/// Compressed data packet body (RFC 9580 §5.6): algorithm octet + data.
pub struct CompressedPacket {
  /// 0 = uncompressed, 1 = ZIP (raw DEFLATE), 2 = ZLIB, 3 = BZip2.
  algo : Int32
  data : Bytes
} derive(Debug)

///|
pub fn CompressedPacket::parse(body : BytesView) -> CompressedPacket raise {
  let r = Reader::new(body)
  let algo = r.read_u8()
  let data = r.read_rest()
  CompressedPacket::{ algo, data, }
}

///|
pub fn CompressedPacket::to_body(self : CompressedPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.algo)
  w.bytes(self.data.exact_view())
  w.to_bytes()
}

///|
/// SEIPD packet body: version 1 (RFC 9580 §5.13.1, the MDC-protected CFB
/// shape) and version 2 (§5.13.2, the chunked AEAD shape).
pub(all) struct SeipdPacket {
  version : Int32
  /// v2 only: symmetric cipher algorithm id.
  cipher_algo : Int32
  /// v2 only: AEAD algorithm id.
  aead_algo : Int32
  /// v2 only: chunk-size octet (`chunk = 2^(c+6)` octets).
  chunk_octet : Int32
  /// v2 only: 32-octet HKDF salt.
  salt : Bytes
  ciphertext : Bytes
} derive(Debug)

///|
pub fn SeipdPacket::cipher_algo(self : SeipdPacket) -> Int32 {
  self.cipher_algo
}

///|
pub fn SeipdPacket::aead_algo(self : SeipdPacket) -> Int32 {
  self.aead_algo
}

///|
pub fn SeipdPacket::chunk_octet(self : SeipdPacket) -> Int32 {
  self.chunk_octet
}

///|
pub fn SeipdPacket::salt(self : SeipdPacket) -> Bytes {
  self.salt
}

///|
/// A v1 SEIPD packet literal.
pub fn SeipdPacket::v1(ciphertext : BytesView) -> SeipdPacket {
  {
    version: 1,
    cipher_algo: 0,
    aead_algo: 0,
    chunk_octet: 0,
    salt: Bytes::new(0),
    ciphertext: ciphertext.to_owned(),
  }
}

///|
pub fn SeipdPacket::parse(body : BytesView) -> SeipdPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  if version == 2 {
    let cipher_algo = r.read_u8()
    let aead_algo = r.read_u8()
    let chunk_octet = r.read_u8()
    let salt = r.read_bytes(32)
    let ct = r.read_rest()
    SeipdPacket::{
      version,
      cipher_algo,
      aead_algo,
      chunk_octet,
      salt,
      ciphertext: ct,
    }
  } else if version == 1 {
    let ct = r.read_rest()
    SeipdPacket::v1(ct)
  } else {
    @error.fail("packet: unsupported SEIPD version \{version}")
  }
}

///|
pub fn SeipdPacket::to_body(self : SeipdPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.version)
  if self.version == 2 {
    w.u8(self.cipher_algo)
    w.u8(self.aead_algo)
    w.u8(self.chunk_octet)
    w.bytes(self.salt.exact_view())
  }
  w.bytes(self.ciphertext.exact_view())
  w.to_bytes()
}

///|
/// Session-key checksum (RFC 9580 §5.1): sum of octets mod 65536.
pub fn session_key_checksum(key : BytesView) -> Int32 {
  let mut sum = 0
  for b in key {
    sum = (sum + b.to_int()) & 0xFFFF
  }
  sum
}

///|
pub extend AeadPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend CompressedPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend LiteralPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PkeskPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SeipdPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SkeskPacket with @moonbitlang/core/debug.Debug::{to_repr}
