///|
/// PKESK v3 packet body (RFC 9580 §5.1).
pub(all) struct PkeskPacket {
  /// Recipient key id (0 for hidden recipients).
  key_id : Bytes
  pub_algo : PubKeyAlgo
  /// RSA: the encrypted session key MPI value. ECDH: the key-wrapped
  /// session key (§5.1.5), serialized after `ecdh_ephemeral`.
  encrypted : Bytes
  /// ECDH only: the MPI value of the ephemeral point (0x40 || X).
  /// Empty for RSA.
  ecdh_ephemeral : Bytes
} derive(Debug)

///|
pub fn PkeskPacket::key_id(self : PkeskPacket) -> Bytes {
  self.key_id
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
  guard version == 3 else {
    @error.fail("packet: unsupported PKESK version \{version}")
  }
  let key_id = r.read_bytes(8)
  let algo = pub_key_algo_of_number(r.read_u8())
  match algo {
    RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => {
      let encrypted = r.read_mpi()
      PkeskPacket::{
        key_id,
        pub_algo: algo,
        encrypted,
        ecdh_ephemeral: Bytes::new(0),
      }
    }
    Ecdh => {
      let eph = r.read_mpi()
      let size = r.read_u8()
      let wrapped = r.read_bytes(size)
      PkeskPacket::{
        key_id,
        pub_algo: algo,
        encrypted: wrapped,
        ecdh_ephemeral: eph,
      }
    }
    _ => {
      let encrypted = r.read_rest()
      PkeskPacket::{
        key_id,
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
  w.u8(3)
  w.bytes(self.key_id.exact_view())
  w.u8(self.pub_algo.number())
  match self.pub_algo {
    Ecdh => {
      w.mpi(self.ecdh_ephemeral.exact_view())
      w.u8(self.encrypted.length())
      w.bytes(self.encrypted.exact_view())
    }
    _ => w.mpi(self.encrypted.exact_view())
  }
  w.to_bytes()
}

///|
/// SKESK packet body, versions 4 (RFC 9580 §5.3.1) and 5 (the 4880bis /
/// crypto-refresh AEAD-wrapped session key GnuPG 2.4 emits under
/// --force-aead). Version 5 adds the AEAD algorithm and an IV; its
/// encrypted session key is sealed with the S2K-derived key directly
/// (the HKDF step belongs to the v6 SKESK, not implemented).
pub(all) struct SkeskPacket {
  version : Int
  /// Symmetric algorithm used for the message; also the default derivation
  /// length selector for the S2K key.
  cipher_algo : Int
  /// AEAD algorithm id for version 5 (0 for version 4).
  aead_algo : Int
  s2k : @s2k.S2k
  /// AEAD IV for version 5 (empty for version 4).
  iv : Bytes
  /// Encrypted session key (v4: algo octet + key, CFB-wrapped; v5: the
  /// AEAD seal of the key alone), present when the S2K key only wraps the
  /// session key. Empty when the S2K derives it directly.
  encrypted_session_key : Bytes
} derive(Debug)

///|
pub fn SkeskPacket::version(self : SkeskPacket) -> Int {
  self.version
}

///|
pub fn SkeskPacket::cipher_algo(self : SkeskPacket) -> Int {
  self.cipher_algo
}

///|
pub fn SkeskPacket::aead_algo(self : SkeskPacket) -> Int {
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
fn aead_iv_len(algo : Int) -> Int raise {
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
  guard version == 4 || version == 5 else {
    @error.fail("packet: unsupported SKESK version \{version}")
  }
  let cipher_algo = r.read_u8()
  let aead_algo = if version == 5 { r.read_u8() } else { 0 }
  let (s2k, used) = @s2k.parse(r.view())
  ignore(r.read_bytes(used))
  let iv = if version == 5 {
    r.read_bytes(aead_iv_len(aead_algo))
  } else {
    Bytes::new(0)
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
  w.u8(self.cipher_algo)
  if self.version == 5 {
    w.u8(self.aead_algo)
  }
  w.bytes(self.s2k.encode().exact_view())
  if self.version == 5 {
    guard self.iv.length() == aead_iv_len(self.aead_algo) else {
      @error.fail("packet: bad SKESK v5 IV length")
    }
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
  version : Int
  cipher_algo : Int
  aead_algo : Int
  chunk_octet : Int
  iv : Bytes
  /// Chunk ciphertexts+tags followed by the final tag.
  ciphertext : Bytes
} derive(Debug)

///|
pub fn AeadPacket::version(self : AeadPacket) -> Int {
  self.version
}

///|
pub fn AeadPacket::cipher_algo(self : AeadPacket) -> Int {
  self.cipher_algo
}

///|
pub fn AeadPacket::aead_algo(self : AeadPacket) -> Int {
  self.aead_algo
}

///|
pub fn AeadPacket::chunk_octet(self : AeadPacket) -> Int {
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
  date : Int
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
pub fn LiteralPacket::date(self : LiteralPacket) -> Int {
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
  let name : String = @utf8.decode(name_bytes.exact_view()) catch { _ => "" }
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
  algo : Int
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
/// SEIPD v1 packet body (RFC 9580 §5.13.1): version octet + ciphertext.
pub(all) struct SeipdPacket {
  version : Int
  ciphertext : Bytes
} derive(Debug)

///|
pub fn SeipdPacket::parse(body : BytesView) -> SeipdPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  let ct = r.read_rest()
  SeipdPacket::{ version, ciphertext: ct, }
}

///|
pub fn SeipdPacket::to_body(self : SeipdPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.version)
  w.bytes(self.ciphertext.exact_view())
  w.to_bytes()
}

///|
/// Session-key checksum (RFC 9580 §5.1): sum of octets mod 65536.
pub fn session_key_checksum(key : BytesView) -> Int {
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
