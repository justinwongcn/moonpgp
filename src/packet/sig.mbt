///|
/// Signature types (RFC 9580 §5.2.1).
pub(all) enum SigType {
  BinaryDocument
  CanonicalTextDocument
  Standalone
  GenericCertification
  PersonaCertification
  CasualCertification
  PositiveCertification
  SubkeyBinding
  PrimaryKeyBinding
  DirectSignature
  KeyRevocation
  SubkeyRevocation
  CertificationRevocation
  Timestamp
  ThirdPartyConfirmation
  Unknown(Int)
} derive(Eq, Debug)

///|
pub fn SigType::number(self : SigType) -> Int {
  match self {
    BinaryDocument => 0
    CanonicalTextDocument => 1
    Standalone => 2
    GenericCertification => 16
    PersonaCertification => 17
    CasualCertification => 18
    PositiveCertification => 19
    SubkeyBinding => 24
    PrimaryKeyBinding => 25
    DirectSignature => 31
    KeyRevocation => 32
    SubkeyRevocation => 40
    CertificationRevocation => 48
    Timestamp => 64
    ThirdPartyConfirmation => 80
    Unknown(n) => n
  }
}

///|
pub fn sig_type_of_number(n : Int) -> SigType {
  match n {
    0 => BinaryDocument
    1 => CanonicalTextDocument
    2 => Standalone
    16 => GenericCertification
    17 => PersonaCertification
    18 => CasualCertification
    19 => PositiveCertification
    24 => SubkeyBinding
    25 => PrimaryKeyBinding
    31 => DirectSignature
    32 => KeyRevocation
    40 => SubkeyRevocation
    48 => CertificationRevocation
    64 => Timestamp
    80 => ThirdPartyConfirmation
    _ => Unknown(n)
  }
}

///|
/// Signature subpacket type IDs (subset, RFC 9580 §5.2.3.1).
pub const SIGSUB_CREATION_TIME : Int = 2

///|
pub const SIGSUB_SIG_EXPIRATION_TIME : Int = 3

///|
pub const SIGSUB_EXPORTABLE_CERTIFICATION : Int = 4

///|
pub const SIGSUB_PREFERRED_SYM_ALGOS : Int = 11

///|
pub const SIGSUB_PREFERRED_HASH_ALGOS : Int = 21

///|
pub const SIGSUB_PREFERRED_COMP_ALGOS : Int = 22

///|
pub const SIGSUB_ISSUER_KEY_ID : Int = 16

///|
pub const SIGSUB_TRUST_SIGNATURE : Int = 5

///|
pub const SIGSUB_REGULAR_EXPRESSION : Int = 6

///|
pub const SIGSUB_REVOCABLE : Int = 7

///|
pub const SIGSUB_KEY_EXPIRATION_TIME : Int = 9

///|
pub const SIGSUB_NOTATION_DATA : Int = 20

///|
pub const SIGSUB_KEY_SERVER_PREFERENCES : Int = 23

///|
pub const SIGSUB_PREFERRED_KEY_SERVER : Int = 24

///|
pub const SIGSUB_PRIMARY_USER_ID : Int = 25

///|
pub const SIGSUB_POLICY_URI : Int = 26

///|
pub const SIGSUB_SIGNATURE_TARGET : Int = 31

///|
pub const SIGSUB_KEY_FLAGS : Int = 27

///|
pub const SIGSUB_SIGNER_USER_ID : Int = 28

///|
pub const SIGSUB_REVOCATION_REASON : Int = 29

///|
pub const SIGSUB_FEATURES : Int = 30

///|
pub const SIGSUB_EMBEDDED_SIGNATURE : Int = 32

///|
pub const SIGSUB_ISSUER_FINGERPRINT : Int = 33

///|
/// A raw signature subpacket: critical bit, type id, body.
pub(all) struct SigSubpacket {
  critical : Bool
  sub_type : Int
  body : Bytes
} derive(Debug, Eq)

///|
pub fn SigSubpacket::critical(self : SigSubpacket) -> Bool {
  self.critical
}

///|
pub fn SigSubpacket::sub_type(self : SigSubpacket) -> Int {
  self.sub_type
}

///|
pub fn SigSubpacket::body(self : SigSubpacket) -> Bytes {
  self.body
}

///|
/// A version 4 signature packet body (RFC 9580 §5.2.3).
pub(all) struct SignaturePacket {
  sig_type : SigType
  pub_algo : PubKeyAlgo
  hash_algo : Int
  hashed_subpackets : Array[SigSubpacket]
  unhashed_subpackets : Array[SigSubpacket]
  /// The hashed subpacket area exactly as it appeared on the wire; third
  /// party signatures must be hashed over these raw bytes, not a
  /// re-serialization (subpacket length encodings may differ).
  raw_hashed_area : Bytes
  /// First two octets of the digest (fast check).
  fast_hash : Int
  /// Algorithm-specific signature material in wire order (RSA: one MPI).
  sig_params : Array[Bytes]
} derive(Debug)

///|
pub fn SignaturePacket::sig_type(self : SignaturePacket) -> SigType {
  self.sig_type
}

///|
pub fn SignaturePacket::pub_algo(self : SignaturePacket) -> PubKeyAlgo {
  self.pub_algo
}

///|
pub fn SignaturePacket::hash_algo(self : SignaturePacket) -> Int {
  self.hash_algo
}

///|
pub fn SignaturePacket::hashed_subpackets(
  self : SignaturePacket,
) -> Array[SigSubpacket] {
  self.hashed_subpackets
}

///|
pub fn SignaturePacket::unhashed_subpackets(
  self : SignaturePacket,
) -> Array[SigSubpacket] {
  self.unhashed_subpackets
}

///|
pub fn SignaturePacket::fast_hash(self : SignaturePacket) -> Int {
  self.fast_hash
}

///|
pub fn SignaturePacket::sig_params(self : SignaturePacket) -> Array[Bytes] {
  self.sig_params
}

///|
fn parse_subpackets(view : BytesView) -> Array[SigSubpacket] raise {
  let out : Array[SigSubpacket] = []
  let r = Reader::new(view)
  while r.remaining() > 0 {
    let first = r.read_u8()
    let len : Int = if first < 192 {
      first
    } else if first < 255 {
      let second = r.read_u8()
      ((first - 192) << 8) + second + 192
    } else {
      r.read_u32()
    }
    let body = r.read_bytes(len)
    guard body.length() >= 1 else {
      @error.fail("packet: zero-length signature subpacket")
    }
    let t = body[0].to_int()
    out.push(SigSubpacket::{
      critical: (t & 0x80) != 0,
      sub_type: t & 0x7F,
      body: body[1:body.length()].to_owned(),
    })
  }
  out
}

///|
fn serialize_subpackets(subs : Array[SigSubpacket]) -> Bytes {
  let w = Writer::new()
  for sp in subs {
    let body_len = sp.body.length() + 1
    if body_len < 192 {
      w.u8(body_len)
    } else if body_len < 8384 {
      let enc = body_len - 192 + 192 * 256
      w.u8(enc >> 8)
      w.u8(enc)
    } else {
      w.u8(255)
      w.u32(body_len)
    }
    let type_octet = if sp.critical { sp.sub_type | 0x80 } else { sp.sub_type }
    w.u8(type_octet)
    w.bytes(sp.body.exact_view())
  }
  w.to_bytes()
}

///|
pub fn SignaturePacket::parse(body : BytesView) -> SignaturePacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 4 else {
    @error.fail("packet: unsupported signature version \{version}")
  }
  let sig_type = sig_type_of_number(r.read_u8())
  let pub_algo = pub_key_algo_of_number(r.read_u8())
  let hash_algo = r.read_u8()
  let hashed_len = r.read_u16()
  let raw_hashed = r.read_bytes(hashed_len)
  let hashed = parse_subpackets(raw_hashed.exact_view())
  let unhashed_len = r.read_u16()
  let unhashed = parse_subpackets(r.read_bytes(unhashed_len).exact_view())
  let fast = r.read_u16()
  let params : Array[Bytes] = []
  match pub_algo {
    RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => params.push(r.read_mpi())
    EdDsaLegacy => {
      // EdDSA legacy carries two MPIs: r then s (RFC 9580 §5.2.3.1).
      params.push(r.read_mpi())
      params.push(r.read_mpi())
    }
    _ =>
      // Unknown material is carried raw so the packet still round-trips.
      params.push(r.read_rest())
  }
  SignaturePacket::{
    sig_type,
    pub_algo,
    hash_algo,
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: raw_hashed,
    fast_hash: fast,
    sig_params: params,
  }
}

///|
pub fn SignaturePacket::to_body(self : SignaturePacket) -> Bytes {
  let w = Writer::new()
  w.u8(4)
  w.u8(self.sig_type.number())
  w.u8(self.pub_algo.number())
  w.u8(self.hash_algo)
  let hashed = match self.raw_hashed_area {
    b if b.length() > 0 => b
    _ => serialize_subpackets(self.hashed_subpackets)
  }
  w.u16(hashed.length())
  w.bytes(hashed.exact_view())
  let unhashed = serialize_subpackets(self.unhashed_subpackets)
  w.u16(unhashed.length())
  w.bytes(unhashed.exact_view())
  w.u16(self.fast_hash)
  for p in self.sig_params {
    w.mpi(p.exact_view())
  }
  w.to_bytes()
}

///|
/// First subpacket body of the given type from `subs`.
pub fn find_subpacket(subs : Array[SigSubpacket], t : Int) -> Bytes? {
  for sp in subs {
    if sp.sub_type == t {
      return Some(sp.body)
    }
  }
  None
}

///|
/// Signature creation time from the hashed subpackets (seconds since epoch).
pub fn SignaturePacket::creation_time(self : SignaturePacket) -> Int? {
  match find_subpacket(self.hashed_subpackets, SIGSUB_CREATION_TIME) {
    Some(b) =>
      if b.length() == 4 {
        Some(
          (b[0].to_int() << 24) |
          (b[1].to_int() << 16) |
          (b[2].to_int() << 8) |
          b[3].to_int(),
        )
      } else {
        None
      }
    None => None
  }
}

///|
/// Issuer key id, preferring the v0.16 subpacket; falls back to the
/// issuer-fingerprint subpacket's trailing key id.
pub fn SignaturePacket::issuer_key_id(self : SignaturePacket) -> Bytes? {
  match find_subpacket(self.hashed_subpackets, SIGSUB_ISSUER_KEY_ID) {
    Some(b) => return Some(b)
    None => ()
  }
  match find_subpacket(self.unhashed_subpackets, SIGSUB_ISSUER_KEY_ID) {
    Some(b) => return Some(b)
    None => ()
  }
  let fp = match
    find_subpacket(self.hashed_subpackets, SIGSUB_ISSUER_FINGERPRINT) {
    Some(f) => f
    None =>
      match
        find_subpacket(self.unhashed_subpackets, SIGSUB_ISSUER_FINGERPRINT) {
        Some(f) => f
        None => return None
      }
  }
  // Body: version octet then fingerprint (20 octets for v4).
  if fp.length() >= 9 {
    Some(fp[fp.length() - 8:fp.length()].to_owned())
  } else {
    None
  }
}

///|
/// Key flags octets from the hashed subpackets.
pub fn SignaturePacket::key_flags(self : SignaturePacket) -> Bytes? {
  match find_subpacket(self.hashed_subpackets, SIGSUB_KEY_FLAGS) {
    Some(b) => Some(b)
    None => None
  }
}

///|
/// The v4 hash prefix: version(4) | type | pubalgo | hashalgo |
/// hashed_len(2) | hashed area (raw wire bytes when available).
pub fn SignaturePacket::hash_prefix(self : SignaturePacket) -> Bytes {
  let w = Writer::new()
  w.u8(4)
  w.u8(self.sig_type.number())
  w.u8(self.pub_algo.number())
  w.u8(self.hash_algo)
  let hashed = match self.raw_hashed_area {
    b if b.length() > 0 => b
    _ => serialize_subpackets(self.hashed_subpackets)
  }
  w.u16(hashed.length())
  w.bytes(hashed.exact_view())
  w.to_bytes()
}

///|
/// The v4 final trailer: 0x04 0xFF and the 4-octet length of everything
/// hashed before it.
pub fn signature_trailer(hashed_body_len : Int) -> Bytes {
  let w = Writer::new()
  w.u8(4)
  w.u8(255)
  w.u32(hashed_body_len)
  w.to_bytes()
}

///|
/// A one-pass signature packet body (RFC 9580 §5.4).
pub(all) struct OnePassSigPacket {
  sig_type : SigType
  hash_algo : Int
  pub_algo : PubKeyAlgo
  key_id : Bytes
  nested : Bool
} derive(Debug)

///|
pub fn OnePassSigPacket::parse(body : BytesView) -> OnePassSigPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 3 else {
    @error.fail("packet: unsupported one-pass signature version \{version}")
  }
  let sig_type = sig_type_of_number(r.read_u8())
  let hash_algo = r.read_u8()
  let pub_algo = pub_key_algo_of_number(r.read_u8())
  let key_id = r.read_bytes(8)
  let nested = r.read_u8() != 0
  OnePassSigPacket::{ sig_type, hash_algo, pub_algo, key_id, nested, }
}

///|
pub fn OnePassSigPacket::to_body(self : OnePassSigPacket) -> Bytes {
  let w = Writer::new()
  w.u8(3)
  w.u8(self.sig_type.number())
  w.u8(self.hash_algo)
  w.u8(self.pub_algo.number())
  w.bytes(self.key_id.exact_view())
  w.u8(if self.nested { 1 } else { 0 })
  w.to_bytes()
}

///|
pub extend OnePassSigPacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SigSubpacket with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SigSubpacket with Eq::{not_equal, equal}

///|
pub extend SigType with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SigType with Eq::{not_equal, equal}

///|
pub extend SignaturePacket with @moonbitlang/core/debug.Debug::{to_repr}
