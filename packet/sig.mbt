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
  Unknown(Int32)
} derive(Eq, Debug)

///|
pub fn SigType::number(self : SigType) -> Int32 {
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
pub fn sig_type_of_number(n : Int32) -> SigType {
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
pub const SIGSUB_CREATION_TIME : Int32 = 2

///|
pub const SIGSUB_SIG_EXPIRATION_TIME : Int32 = 3

///|
pub const SIGSUB_EXPORTABLE_CERTIFICATION : Int32 = 4

///|
pub const SIGSUB_PREFERRED_SYM_ALGOS : Int32 = 11

///|
pub const SIGSUB_PREFERRED_HASH_ALGOS : Int32 = 21

///|
pub const SIGSUB_PREFERRED_COMP_ALGOS : Int32 = 22

///|
pub const SIGSUB_ISSUER_KEY_ID : Int32 = 16

///|
pub const SIGSUB_TRUST_SIGNATURE : Int32 = 5

///|
pub const SIGSUB_REGULAR_EXPRESSION : Int32 = 6

///|
pub const SIGSUB_REVOCABLE : Int32 = 7

///|
pub const SIGSUB_KEY_EXPIRATION_TIME : Int32 = 9

///|
pub const SIGSUB_NOTATION_DATA : Int32 = 20

///|
pub const SIGSUB_KEY_SERVER_PREFERENCES : Int32 = 23

///|
pub const SIGSUB_PREFERRED_KEY_SERVER : Int32 = 24

///|
pub const SIGSUB_PRIMARY_USER_ID : Int32 = 25

///|
pub const SIGSUB_POLICY_URI : Int32 = 26

///|
pub const SIGSUB_SIGNATURE_TARGET : Int32 = 31

///|
pub const SIGSUB_KEY_FLAGS : Int32 = 27

///|
/// Preferred AEAD Ciphersuites (RFC 9580 §5.2.3.15). Table 5 of RFC 9580
/// assigns type 39; type 34 is Reserved, so using it here made the
/// preference invisible to every other implementation (and hid theirs
/// from us) while our own round-trip tests stayed green.
pub const SIGSUB_PREFERRED_AEAD : Int32 = 39

///|
/// The Features flags octet (RFC 9580 §5.2.3.32): 0x01 = v1 SEIPD,
/// 0x08 = v2 SEIPD.
pub const FEATURE_SEIPD_V1 : Int32 = 0x01

///|
pub const FEATURE_SEIPD_V2 : Int32 = 0x08

///|
pub const SIGSUB_SIGNER_USER_ID : Int32 = 28

///|
pub const SIGSUB_REVOCATION_REASON : Int32 = 29

///|
pub const SIGSUB_FEATURES : Int32 = 30

///|
pub const SIGSUB_EMBEDDED_SIGNATURE : Int32 = 32

///|
pub const SIGSUB_ISSUER_FINGERPRINT : Int32 = 33

///|
/// A raw signature subpacket: critical bit, type id, body.
pub(all) struct SigSubpacket {
  critical : Bool
  sub_type : Int32
  body : Bytes
} derive(Debug, Eq)

///|
pub fn SigSubpacket::critical(self : SigSubpacket) -> Bool {
  self.critical
}

///|
pub fn SigSubpacket::sub_type(self : SigSubpacket) -> Int32 {
  self.sub_type
}

///|
pub fn SigSubpacket::body(self : SigSubpacket) -> Bytes {
  self.body
}

///|
/// A version 4 or version 6 signature packet body (RFC 9580 §5.2.3).
/// Version 6 differs in the subpacket-area length widths (4 octets), the
/// trailing salt, the trailer's version octet, and raw (non-MPI) Ed25519
/// signature material.
pub(all) struct SignaturePacket {
  version : Int32
  sig_type : SigType
  pub_algo : PubKeyAlgo
  hash_algo : Int32
  hashed_subpackets : Array[SigSubpacket]
  unhashed_subpackets : Array[SigSubpacket]
  /// The hashed subpacket area exactly as it appeared on the wire; third
  /// party signatures must be hashed over these raw bytes, not a
  /// re-serialization (subpacket length encodings may differ).
  raw_hashed_area : Bytes
  /// First two octets of the digest (fast check).
  fast_hash : Int32
  /// v6 only: the 16/24/32-octet salt, hashed before the data and NOT
  /// counted in the trailer length. Empty for v4.
  salt : Bytes
  /// Algorithm-specific signature material in wire order (RSA: one MPI;
  /// EdDSA legacy: two MPIs; Ed25519 v6: one raw 64-octet blob).
  sig_params : Array[Bytes]
} derive(Debug)

///|
pub fn SignaturePacket::version(self : SignaturePacket) -> Int32 {
  self.version
}

///|
pub fn SignaturePacket::salt(self : SignaturePacket) -> Bytes {
  self.salt
}

///|
pub fn SignaturePacket::sig_type(self : SignaturePacket) -> SigType {
  self.sig_type
}

///|
pub fn SignaturePacket::pub_algo(self : SignaturePacket) -> PubKeyAlgo {
  self.pub_algo
}

///|
pub fn SignaturePacket::hash_algo(self : SignaturePacket) -> Int32 {
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
pub fn SignaturePacket::fast_hash(self : SignaturePacket) -> Int32 {
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
    let len : Int32 = if first < 192 {
      first
    } else if first < 255 {
      let second = r.read_u8()
      ((first - 192) << 8) + second + 192
    } else {
      r.read_u32()
    }
    let body = r.read_bytes(len)
    guard body.length() >= 1 else {
      @error.malformed("packet: zero-length signature subpacket")
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
/// RFC 9580 §9.5 Table 23: the v6 signature salt size for a hash
/// algorithm. Only SHA-2/SHA-3 have v6 salt sizes (MD5/SHA-1/RIPEMD-160
/// are "N/A").
pub fn salt_size_of_hash(hash_id : Int32) -> Int32 raise {
  match hash_id {
    8 | 11 | 12 => 16 // SHA-256, SHA-224, SHA3-256
    9 => 24 // SHA-384
    10 | 14 => 32 // SHA-512, SHA3-512
    _ =>
      @error.unsupported(
        "packet: hash algorithm \{hash_id} has no v6 signature salt size",
      )
  }
}

///|
pub fn SignaturePacket::parse(body : BytesView) -> SignaturePacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 4 || version == 6 else {
    @error.unsupported("packet: unsupported signature version \{version}")
  }
  let v6 = version == 6
  let sig_type = sig_type_of_number(r.read_u8())
  let pub_algo = pub_key_algo_of_number(r.read_u8())
  let hash_algo = r.read_u8()
  let hashed_len : Int32 = if v6 { r.read_u32() } else { r.read_u16() }
  let raw_hashed = r.read_bytes(hashed_len)
  let hashed = parse_subpackets(raw_hashed.exact_view())
  let unhashed_len : Int32 = if v6 { r.read_u32() } else { r.read_u16() }
  let unhashed = parse_subpackets(r.read_bytes(unhashed_len).exact_view())
  let fast = r.read_u16()
  let salt : Bytes = if v6 {
    let salt_len = r.read_u8()
    let expected = salt_size_of_hash(hash_algo)
    guard salt_len == expected else {
      @error.malformed(
        "packet: v6 signature salt of \{salt_len} octets does not match the hash algorithm (expected \{expected})",
      )
    }
    r.read_bytes(salt_len)
  } else {
    Bytes::new(0)
  }
  let params : Array[Bytes] = []
  match pub_algo {
    RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly => params.push(r.read_mpi())
    EdDsaLegacy => {
      // RFC 9580 §5.2.3.3.1: "Ed25519Legacy MUST NOT be used in Signature
      // packets version 6 or above" — only for reading historic v4 keys.
      guard version < 6 else {
        @error.malformed(
          "packet: EdDsaLegacy must not be used in a v6 signature packet",
        )
      }
      // EdDSA legacy carries two MPIs: r then s (RFC 9580 §5.2.3.1).
      params.push(r.read_mpi())
      params.push(r.read_mpi())
    }
    Ed25519 => {
      // v6 Ed25519 carries 64 raw octets, not MPIs (§5.2.3.4).
      let sig = r.read_rest()
      guard sig.length() == 64 else {
        @error.malformed(
          "packet: an Ed25519 signature must be 64 octets, got \{sig.length()}",
        )
      }
      params.push(sig)
    }
    _ =>
      // Unknown material is carried raw so the packet still round-trips.
      params.push(r.read_rest())
  }
  SignaturePacket::{
    version,
    sig_type,
    pub_algo,
    hash_algo,
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: raw_hashed,
    fast_hash: fast,
    salt,
    sig_params: params,
  }
}

///|
pub fn SignaturePacket::to_body(self : SignaturePacket) -> Bytes {
  let w = Writer::new()
  let v6 = self.version >= 6
  w.u8(self.version)
  w.u8(self.sig_type.number())
  w.u8(self.pub_algo.number())
  w.u8(self.hash_algo)
  let hashed = match self.raw_hashed_area {
    b if b.length() > 0 => b
    _ => serialize_subpackets(self.hashed_subpackets)
  }
  if v6 {
    w.u32(hashed.length())
  } else {
    w.u16(hashed.length())
  }
  w.bytes(hashed.exact_view())
  let unhashed = serialize_subpackets(self.unhashed_subpackets)
  if v6 {
    w.u32(unhashed.length())
  } else {
    w.u16(unhashed.length())
  }
  w.bytes(unhashed.exact_view())
  w.u16(self.fast_hash)
  if v6 {
    w.u8(self.salt.length())
    w.bytes(self.salt.exact_view())
  }
  for p in self.sig_params {
    match self.pub_algo {
      Ed25519 => w.bytes(p.exact_view())
      _ => w.mpi(p.exact_view())
    }
  }
  w.to_bytes()
}

///|
/// The signature subpacket types this implementation recognizes: exactly
/// the set with constants defined above. RFC 9580 §5.2.3.6: an evaluator
/// that encounters an unknown subpacket marked critical SHOULD consider
/// the whole signature in error (the bit is honored in both the hashed
/// and the unhashed area), so verifiers consult this set via
/// `SignaturePacket::has_unknown_critical_subpacket`.
pub fn is_known_sigsub_type(t : Int32) -> Bool {
  t == SIGSUB_CREATION_TIME ||
  t == SIGSUB_SIG_EXPIRATION_TIME ||
  t == SIGSUB_EXPORTABLE_CERTIFICATION ||
  t == SIGSUB_TRUST_SIGNATURE ||
  t == SIGSUB_REGULAR_EXPRESSION ||
  t == SIGSUB_REVOCABLE ||
  t == SIGSUB_KEY_EXPIRATION_TIME ||
  t == SIGSUB_PREFERRED_SYM_ALGOS ||
  t == SIGSUB_ISSUER_KEY_ID ||
  t == SIGSUB_NOTATION_DATA ||
  t == SIGSUB_PREFERRED_HASH_ALGOS ||
  t == SIGSUB_PREFERRED_COMP_ALGOS ||
  t == SIGSUB_KEY_SERVER_PREFERENCES ||
  t == SIGSUB_PREFERRED_KEY_SERVER ||
  t == SIGSUB_PRIMARY_USER_ID ||
  t == SIGSUB_POLICY_URI ||
  t == SIGSUB_KEY_FLAGS ||
  t == SIGSUB_SIGNER_USER_ID ||
  t == SIGSUB_REVOCATION_REASON ||
  t == SIGSUB_FEATURES ||
  t == SIGSUB_SIGNATURE_TARGET ||
  t == SIGSUB_EMBEDDED_SIGNATURE ||
  t == SIGSUB_ISSUER_FINGERPRINT ||
  t == SIGSUB_PREFERRED_AEAD
}

///|
/// True when any hashed or unhashed subpacket is marked critical but not
/// in the recognized set — the signature MUST be treated as in error.
pub fn SignaturePacket::has_unknown_critical_subpacket(
  self : SignaturePacket,
) -> Bool {
  let unknown_critical = fn(sp : SigSubpacket) -> Bool {
    sp.critical && !is_known_sigsub_type(sp.sub_type)
  }
  for sp in self.hashed_subpackets {
    if unknown_critical(sp) {
      return true
    }
  }
  for sp in self.unhashed_subpackets {
    if unknown_critical(sp) {
      return true
    }
  }
  false
}

///|
/// First subpacket body of the given type from `subs`.
pub fn find_subpacket(subs : Array[SigSubpacket], t : Int32) -> Bytes? {
  for sp in subs {
    if sp.sub_type == t {
      return Some(sp.body)
    }
  }
  None
}

///|
/// Signature creation time from the hashed subpackets (seconds since epoch).
pub fn SignaturePacket::creation_time(self : SignaturePacket) -> Int32? {
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
/// Issuer key id, preferring the type 16 (Issuer Key ID) subpacket; falls
/// back to the issuer-fingerprint subpacket's trailing key id.
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
  // Body: version octet then fingerprint (20 octets for v4, 32 for v6).
  if fp.length() >= 9 {
    let fp_version = fp[0].to_int()
    if fp_version >= 5 {
      // v6: the key id is the HIGH-order 64 bits of the fingerprint.
      Some(fp[1:9].to_owned())
    } else {
      Some(fp[fp.length() - 8:fp.length()].to_owned())
    }
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
/// 4-octet big-endian seconds value of a lifetime subpacket body, or 0
/// when absent/malformed (0 = "never expires", so callers need not
/// distinguish the two).
fn lifetime_secs(subs : Array[SigSubpacket], sub_type : Int32) -> Int32 {
  match find_subpacket(subs, sub_type) {
    Some(b) =>
      if b.length() == 4 {
        (b[0].to_int() << 24) |
        (b[1].to_int() << 16) |
        (b[2].to_int() << 8) |
        b[3].to_int()
      } else {
        0
      }
    None => 0
  }
}

///|
/// The Key Expiration Time subpacket (RFC 9580 §5.2.3.6): seconds after
/// the associated key's creation time; 0 = the key never expires.
pub fn SignaturePacket::key_expiration_time(self : SignaturePacket) -> Int32 {
  lifetime_secs(self.hashed_subpackets, SIGSUB_KEY_EXPIRATION_TIME)
}

///|
/// The Signature Expiration Time subpacket (RFC 9580 §5.2.3.10): seconds
/// after the signature's creation time; 0 = the signature never expires.
pub fn SignaturePacket::sig_expiration_time(self : SignaturePacket) -> Int32 {
  lifetime_secs(self.hashed_subpackets, SIGSUB_SIG_EXPIRATION_TIME)
}

///|
/// The Features flags octet (RFC 9580 §5.2.3.32), when present.
pub fn SignaturePacket::features(self : SignaturePacket) -> Bytes? {
  find_subpacket(self.hashed_subpackets, SIGSUB_FEATURES)
}

///|
/// True when the Features subpacket advertises the v2 SEIPD flag
/// (RFC 9580 §5.2.3.32/§13.7).
pub fn SignaturePacket::supports_seipd_v2(self : SignaturePacket) -> Bool {
  match self.features() {
    Some(f) => f.length() > 0 && (f[0].to_int() & FEATURE_SEIPD_V2) != 0
    None => false
  }
}

///|
/// The Preferred AEAD Ciphersuites list as (cipher, AEAD) pairs, most
/// preferred first (RFC 9580 §5.2.3.15). A trailing odd octet is ignored.
pub fn SignaturePacket::preferred_aead(
  self : SignaturePacket,
) -> Array[(Int32, Int32)]? {
  match find_subpacket(self.hashed_subpackets, SIGSUB_PREFERRED_AEAD) {
    Some(b) => {
      let out : Array[(Int32, Int32)] = []
      let mut i = 0
      while i + 1 < b.length() {
        out.push((b[i].to_int(), b[i + 1].to_int()))
        i = i + 2
      }
      Some(out)
    }
    None => None
  }
}

///|
/// The hash prefix: version | type | pubalgo | hashalgo |
/// hashed_len | hashed area (raw wire bytes when available). Version 6
/// uses a 4-octet subpacket-area length (RFC 9580 §5.2.3).
pub fn SignaturePacket::hash_prefix(self : SignaturePacket) -> Bytes {
  let w = Writer::new()
  let v6 = self.version >= 6
  w.u8(self.version)
  w.u8(self.sig_type.number())
  w.u8(self.pub_algo.number())
  w.u8(self.hash_algo)
  let hashed = match self.raw_hashed_area {
    b if b.length() > 0 => b
    _ => serialize_subpackets(self.hashed_subpackets)
  }
  if v6 {
    w.u32(hashed.length())
  } else {
    w.u16(hashed.length())
  }
  w.bytes(hashed.exact_view())
  w.to_bytes()
}

///|
/// The final trailer: 0x04|0x06 0xFF and the 4-octet length of everything
/// hashed before it (RFC 9580 §5.2.4).
pub fn signature_trailer(version : Int32, hashed_body_len : Int32) -> Bytes {
  let w = Writer::new()
  w.u8(version)
  w.u8(255)
  w.u32(hashed_body_len)
  w.to_bytes()
}

///|
/// A one-pass signature packet body: version 3 (RFC 9580 §5.4, what a v4
/// key emits) and version 6 (the same fields plus a hash salt and the
/// 32-octet signing-key fingerprint, and with the 8-octet key id gone).
pub(all) struct OnePassSigPacket {
  version : Int32
  sig_type : SigType
  hash_algo : Int32
  pub_algo : PubKeyAlgo
  /// v3 only: the 8-octet signing key id.
  key_id : Bytes
  /// v6 only: the hash salt (its size comes from the hash algorithm).
  salt : Bytes
  /// v6 only: the 32-octet signing key fingerprint.
  fingerprint : Bytes
  nested : Bool
} derive(Debug)

///|
pub fn OnePassSigPacket::version(self : OnePassSigPacket) -> Int32 {
  self.version
}

///|
pub fn OnePassSigPacket::key_id(self : OnePassSigPacket) -> Bytes {
  self.key_id
}

///|
pub fn OnePassSigPacket::salt(self : OnePassSigPacket) -> Bytes {
  self.salt
}

///|
pub fn OnePassSigPacket::fingerprint(self : OnePassSigPacket) -> Bytes {
  self.fingerprint
}

///|
pub fn OnePassSigPacket::parse(body : BytesView) -> OnePassSigPacket raise {
  let r = Reader::new(body)
  let version = r.read_u8()
  guard version == 3 || version == 6 else {
    @error.unsupported(
      "packet: unsupported one-pass signature version \{version}",
    )
  }
  let sig_type = sig_type_of_number(r.read_u8())
  let hash_algo = r.read_u8()
  let pub_algo = pub_key_algo_of_number(r.read_u8())
  let mut key_id = Bytes::new(0)
  let mut salt = Bytes::new(0)
  let mut fingerprint = Bytes::new(0)
  if version == 6 {
    let salt_len = r.read_u8()
    // RFC 9580 §5.4: the size MUST match the hash algorithm's Table 23
    // value (a mismatch is malformed, §5.2.5) — same rule the Signature
    // packet enforces when parsing.
    guard salt_len == salt_size_of_hash(hash_algo) else {
      @error.malformed(
        "packet: one-pass signature salt size \{salt_len} does not match hash algorithm \{hash_algo}",
      )
    }
    salt = r.read_bytes(salt_len)
    fingerprint = r.read_bytes(32)
  } else {
    key_id = r.read_bytes(8)
  }
  let nested = r.read_u8() != 0
  OnePassSigPacket::{
    version,
    sig_type,
    hash_algo,
    pub_algo,
    key_id,
    salt,
    fingerprint,
    nested,
  }
}

///|
pub fn OnePassSigPacket::to_body(self : OnePassSigPacket) -> Bytes {
  let w = Writer::new()
  w.u8(self.version)
  w.u8(self.sig_type.number())
  w.u8(self.hash_algo)
  w.u8(self.pub_algo.number())
  if self.version == 6 {
    w.u8(self.salt.length())
    w.bytes(self.salt.exact_view())
    w.bytes(self.fingerprint.exact_view())
  } else {
    w.bytes(self.key_id.exact_view())
  }
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

///|
/// True when the hashed area carries a Primary User ID subpacket (RFC
/// 9580 §5.2.3.20) with a nonzero flag octet — the marker gpg writes on
/// the one certification that names the certificate's primary identity.
pub fn SignaturePacket::is_primary_user_id(self : SignaturePacket) -> Bool {
  match find_subpacket(self.hashed_subpackets, SIGSUB_PRIMARY_USER_ID) {
    Some(body) => body.length() > 0 && body[0].to_int() != 0
    None => false
  }
}
