///|
/// Key lifecycle (M1): expiry, revocation and capability checks aligned
/// with gopenpgp's `Key.IsExpired / IsRevoked / CanEncrypt / CanVerify`.
///
/// Every function takes `now` as seconds since the Unix epoch; `now = 0`
/// disables all time checks — the non-native targets have no clock
/// (`@primitives.unix_now` yields 0 there), so behavior degrades to the
/// pre-lifecycle structural rules instead of spuriously failing.

///|
/// Key flag bits (RFC 9580 §5.2.3.29). The capability masks used here
/// span octet 0 only, where all the classic capabilities live.
const FLAG_CERTIFY : Int32 = 0x01

///|
const FLAG_SIGN : Int32 = 0x02

///|
const FLAG_ENCRYPT_COMM : Int32 = 0x04

///|
const FLAG_ENCRYPT_STORAGE : Int32 = 0x08

///|
const FLAG_ENCRYPT : Int32 = FLAG_ENCRYPT_COMM | FLAG_ENCRYPT_STORAGE

///|
const FLAG_SIGN_OR_CERTIFY : Int32 = FLAG_SIGN | FLAG_CERTIFY

///|
/// True when a key packet expired at `now`: the governing signature's
/// Key Expiration Time is nonzero and `now` lies after the key's creation
/// time plus that many seconds (go-crypto's `keyExpired` semantics: the
/// lifetime counts from the key packet's creation, not the signature's).
fn packet_expired_at(
  packet : @packet.PublicKeyPacket,
  governing_sig : @packet.SignaturePacket?,
  now : Int64,
) -> Bool {
  if now == 0L {
    return false
  }
  let lifetime = match governing_sig {
    Some(s) => s.key_expiration_time()
    None => 0
  }
  if lifetime == 0 {
    return false
  }
  now > (packet.creation_time + lifetime).to_int64()
}

///|
/// True when a signature has itself expired at `now`: its Signature
/// Expiration Time is nonzero and `now` lies after its creation time plus
/// that many seconds. An expired governing signature leaves the component
/// it certifies without a current statement of capability.
fn sig_expired_at(sig : @packet.SignaturePacket, now : Int64) -> Bool {
  if now == 0L {
    return false
  }
  let lifetime = sig.sig_expiration_time()
  if lifetime == 0 {
    return false
  }
  match sig.creation_time() {
    Some(created) => now > (created + lifetime).to_int64()
    None => false
  }
}

///|
fn sig_expired_opt(sig : @packet.SignaturePacket?, now : Int64) -> Bool {
  match sig {
    Some(s) => sig_expired_at(s, now)
    None => false
  }
}

///|
/// True when any stored primary-key revocation verifies over the key and
/// has already taken effect at `now`. A revocation whose cryptographic
/// check fails or errors is ignored — an invalid revocation must not be
/// able to disable a key. `now = 0` still validates the signature but
/// ignores effective-date questions.
fn primary_revoked_at(
  revocations : Array[@packet.SignaturePacket],
  primary : @packet.PublicKeyPacket,
  now : Int64,
) -> Bool {
  for sig in revocations {
    let verified = verify_key_signature(sig, primary, primary, direct=true) catch {
      _ => false
    }
    if revocation_effective_at(sig, now) && verified {
      return true
    }
  }
  false
}

///|
/// True when a subkey revocation verifies over (primary, subkey) and has
/// taken effect at `now`.
fn subkey_revoked_at(
  sig : @packet.SignaturePacket?,
  primary : @packet.PublicKeyPacket,
  subkey : @packet.PublicKeyPacket,
  now : Int64,
) -> Bool {
  match sig {
    Some(s) => {
      let verified = verify_key_signature(s, primary, subkey) catch {
        _ => false
      }
      if revocation_effective_at(s, now) && verified {
        return true
      }
    }
    None => ()
  }
  false
}

///|
/// A future-dated revocation has not taken effect yet; undated ones are
/// treated as immediately effective. `now = 0` (no time) lets every
/// stored revocation through to the cryptographic check.
fn revocation_effective_at(sig : @packet.SignaturePacket, now : Int64) -> Bool {
  if now == 0L {
    return true
  }
  match sig.creation_time() {
    Some(created) => created <= now.to_int()
    None => true
  }
}

///|
/// Key flags octet 0 from a signature's hashed area; None when the
/// subpacket is absent, which means "assume every capability" (the
/// legacy rule gopenpgp encodes as `FlagsValid = false`).
fn governing_flags(sig : @packet.SignaturePacket?) -> Int32? {
  match sig {
    Some(s) =>
      match s.key_flags() {
        Some(b) => if b.length() > 0 { Some(b[0].to_int()) } else { None }
        None => None
      }
    None => None
  }
}

///|
/// Usable for `capability` at `now`: the governing signature's flags
/// permit it (or are absent), the packet has not expired, and the
/// governing signature has not itself expired.
fn component_usable(
  packet : @packet.PublicKeyPacket,
  governing_sig : @packet.SignaturePacket?,
  capability : Int32,
  now : Int64,
) -> Bool {
  let flag_ok = match governing_flags(governing_sig) {
    Some(f) => (f & capability) != 0
    None => true
  }
  flag_ok &&
  !packet_expired_at(packet, governing_sig, now) &&
  !sig_expired_opt(governing_sig, now)
}

///|
/// True when the primary key expired at `now`, per the Key Expiration
/// Time of its certification (or, failing that, its Direct Key
/// signature). Subkey expiry is judged separately inside `can_encrypt`.
pub fn PublicKey::is_expired(self : PublicKey, now : Int64) -> Bool {
  if packet_expired_at(self.primary, Some(self.self_signature()), now) {
    return true
  }
  match self.direct_signature {
    Some(d) => packet_expired_at(self.primary, Some(d), now)
    None => false
  }
}

///|
/// True when a cryptographically valid, already-effective self-revocation
/// of the primary key is on record. Subkey revocations only affect
/// `can_encrypt` (they say nothing about the primary).
pub fn PublicKey::is_revoked(self : PublicKey, now : Int64) -> Bool {
  primary_revoked_at(self.revocations, self.primary, now)
}

///|
/// The encryption-capable packet to use at `now`: the last usable
/// encryption subkey in wire order (each judged by its own binding —
/// flags, expiry, revocation), otherwise the primary for RSA. None when
/// nothing on the key may encrypt at `now`.
pub fn PublicKey::encryption_packet_at(
  self : PublicKey,
  now : Int64,
) -> @packet.PublicKeyPacket? {
  let mut chosen : @packet.PublicKeyPacket? = None
  for c in self.subkeys {
    if !subkey_revoked_at(c.revocation, self.primary, c.key, now) &&
      component_usable(c.key, Some(c.binding), FLAG_ENCRYPT, now) {
      chosen = Some(c.key)
    }
  }
  match chosen {
    Some(k) => return Some(k)
    None => ()
  }
  if self.primary.algo().is_rsa() &&
    component_usable(
      self.primary,
      Some(self.self_signature()),
      FLAG_ENCRYPT,
      now,
    ) {
    return Some(self.primary)
  }
  None
}

///|
/// True when, at `now`, the key has an encryption-capable component:
/// neither the key nor the subkey is revoked, some component carries the
/// encryption key flags (absence of the subpacket counts as capable) and
/// that component has not expired.
pub fn PublicKey::can_encrypt(self : PublicKey, now : Int64) -> Bool {
  if self.is_revoked(now) {
    return false
  }
  self.encryption_packet_at(now) is Some(_)
}

///|
/// True when, at `now`, some component may sign or certify: not revoked,
/// primary (or any subkey) flags permit signing/certifying, and the
/// governing signatures have not expired.
pub fn PublicKey::can_verify(self : PublicKey, now : Int64) -> Bool {
  if self.is_revoked(now) {
    return false
  }
  if component_usable(
      self.primary,
      Some(self.self_signature()),
      FLAG_SIGN_OR_CERTIFY,
      now,
    ) {
    return true
  }
  for c in self.subkeys {
    if component_usable(c.key, Some(c.binding), FLAG_SIGN_OR_CERTIFY, now) {
      return true
    }
  }
  false
}

///|
/// See `PublicKey::is_expired`. Delegates to the public half.
pub fn PrivateKey::is_expired(self : PrivateKey, now : Int64) -> Bool {
  self.to_public().is_expired(now)
}

///|
/// See `PublicKey::is_revoked`. Delegates to the public half.
pub fn PrivateKey::is_revoked(self : PrivateKey, now : Int64) -> Bool {
  self.to_public().is_revoked(now)
}

///|
/// See `PublicKey::can_encrypt`. Delegates to the public half.
pub fn PrivateKey::can_encrypt(self : PrivateKey, now : Int64) -> Bool {
  self.to_public().can_encrypt(now)
}

///|
/// See `PublicKey::can_verify`. Delegates to the public half.
pub fn PrivateKey::can_verify(self : PrivateKey, now : Int64) -> Bool {
  self.to_public().can_verify(now)
}
