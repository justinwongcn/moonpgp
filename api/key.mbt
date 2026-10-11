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
pub extend PrivateKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PublicKey with @moonbitlang/core/debug.Debug::{to_repr}
