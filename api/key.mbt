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
  /// Every bound subkey in wire order (N2). Import guarantees each entry's
  /// binding signature verifies over (primary, subkey) — a subkey without
  /// a binding is rejected rather than trusted (RFC 9580 §10.1).
  subkeys : Array[SecretSubkeyCert]
  /// Primary-key revocation signatures (type 0x20) found on import;
  /// verified lazily by `is_revoked` (their validity is time-dependent).
  revocations : Array[@packet.SignaturePacket]
} derive(Debug)

///|
/// The public half of a transferable key. Read-only like `PrivateKey`;
/// obtain values via `to_public` / `from_armored` / `from_bytes`.
pub struct PublicKey {
  primary : @packet.PublicKeyPacket
  /// All certified User IDs, in wire order (M5).
  user_ids : Array[UserIdBinding]
  direct_signature : @packet.SignaturePacket?
  /// Every bound subkey in wire order (N2); see `PrivateKey::subkeys`.
  subkeys : Array[SubkeyCert]
  /// Primary-key revocation signatures (type 0x20) found on import.
  revocations : Array[@packet.SignaturePacket]
} derive(Debug)

///|
/// One bound subkey of a public transferable key: the public key packet,
/// the SubkeyBinding signature by the primary (import-verified), and the
/// SubkeyRevocation signature when the wire carried one.
pub(all) struct SubkeyCert {
  key : @packet.PublicKeyPacket
  binding : @packet.SignaturePacket
  revocation : @packet.SignaturePacket?
} derive(Debug)

///|
/// The private-key half of one bound subkey: the secret key packet plus
/// the same binding/revocation signatures as its public twin.
pub(all) struct SecretSubkeyCert {
  secret : @packet.SecretKeyPacket
  binding : @packet.SignaturePacket
  revocation : @packet.SignaturePacket?
} derive(Debug)

///|
/// One certified User ID: the identifier plus the self-signature that
/// binds it to the primary key. A revoked User ID keeps its place on the
/// certificate with the CertificationRevocation signature attached —
/// that is how the wire tells verifiers the identity is no longer valid.
pub(all) struct UserIdBinding {
  user_id : String
  self_signature : @packet.SignaturePacket
  revocation : @packet.SignaturePacket?
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
/// The primary User ID string: the one whose self-certification carries
/// the Primary User ID flag, else the first certified User ID; empty for
/// a bare v6 key.
pub fn PrivateKey::user_id(self : PrivateKey) -> String {
  primary_user_id_of(self.user_ids)
}

///|
fn primary_user_id_of(bindings : Array[UserIdBinding]) -> String {
  let mut first = ""
  for b in bindings {
    if first == "" {
      first = b.user_id
    }
    if b.self_signature.is_primary_user_id() {
      return b.user_id
    }
  }
  first
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
/// The primary User ID string: the one whose self-certification carries
/// the Primary User ID flag, else the first certified User ID; empty for
/// a bare v6 key.
pub fn PublicKey::user_id(self : PublicKey) -> String {
  primary_user_id_of(self.user_ids)
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
/// The public key packet of an encryption-capable key, structurally (no
/// clock): the last subkey whose binding flags permit encryption (absent
/// flags count as capable), otherwise the RSA primary key. The
/// lifecycle-aware choice is `encryption_packet_at`.
pub fn PublicKey::encryption_key(self : PublicKey) -> @packet.PublicKeyPacket? {
  let mut chosen : @packet.PublicKeyPacket? = None
  for c in self.subkeys {
    match governing_flags(Some(c.binding)) {
      Some(f) => if (f & FLAG_ENCRYPT) != 0 { chosen = Some(c.key) }
      None => chosen = Some(c.key)
    }
  }
  match chosen {
    Some(k) => return Some(k)
    None => ()
  }
  if self.primary.algo().is_rsa() {
    Some(self.primary)
  } else {
    None
  }
}

///|
/// Strip the secret material, producing a transferable public key.
pub fn PrivateKey::to_public(self : PrivateKey) -> PublicKey {
  let subkeys : Array[SubkeyCert] = []
  for c in self.subkeys {
    subkeys.push(SubkeyCert::{
      key: c.secret.public,
      binding: c.binding,
      revocation: c.revocation,
    })
  }
  PublicKey::{
    primary: self.primary.public,
    user_ids: self.user_ids,
    direct_signature: self.direct_signature,
    subkeys,
    revocations: self.revocations,
  }
}

///|
pub extend PrivateKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PublicKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SubkeyCert with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SecretSubkeyCert with @moonbitlang/core/debug.Debug::{to_repr}
