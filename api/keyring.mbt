///|
/// A collection of public and private keys with id lookup, mirroring the
/// gopenpgp KeyRing role.
pub struct KeyRing {
  priv public_keys : Array[PublicKey]
  priv private_keys : Array[PrivateKey]
} derive(Debug)

///|
/// Create an empty key ring.
pub fn KeyRing::new() -> KeyRing {
  KeyRing::{ public_keys: [], private_keys: [], }
}

///|
/// Add a public key (available to encryption/verification lookups).
pub fn KeyRing::add_public(self : KeyRing, key : PublicKey) -> Unit {
  self.public_keys.push(key)
}

///|
/// Add a private key (available to decryption lookups).
pub fn KeyRing::add_private(self : KeyRing, key : PrivateKey) -> Unit {
  self.private_keys.push(key)
}

///|
/// Number of public keys in the ring.
pub fn KeyRing::public_count(self : KeyRing) -> Int32 {
  self.public_keys.length()
}

///|
/// Number of private keys in the ring.
pub fn KeyRing::private_count(self : KeyRing) -> Int32 {
  self.private_keys.length()
}

///|
/// All public key packets (primary + subkeys) of a key, with their packets.
fn all_public_packets(key : PublicKey) -> Array[@packet.PublicKeyPacket] {
  let out = [key.primary]
  for c in key.subkeys {
    out.push(c.key)
  }
  out
}

///|
/// True when the packet is an encryption-capable component of `key` that
/// is still usable at `now` (key/subkey not revoked, flags permit —
/// absent flags count as capable —, nothing expired). Each subkey is
/// judged by its own binding (N2).
fn key_packet_encryption_usable_at(
  key : PublicKey,
  packet : @packet.PublicKeyPacket,
  now : Int64,
) -> Bool raise {
  if key.is_revoked(now) {
    return false
  }
  for c in key.subkeys {
    if c.key.key_id().equal(packet.key_id()) {
      return !subkey_revoked_at(c.revocation, key.primary, c.key, now) &&
        component_usable(c.key, Some(c.binding), FLAG_ENCRYPT, now)
    }
  }
  key.primary.algo().is_rsa() &&
  component_usable(key.primary, Some(key.self_signature()), FLAG_ENCRYPT, now)
}

///|
/// True when the packet is a component of `key` that may verify at `now`
/// (not revoked, sign/certify flags permit, nothing expired). The matched
/// packet is judged by its own binding (N2): a sibling subkey's health
/// says nothing about the subkey that actually issued the signature.
fn key_packet_verify_usable_at(
  key : PublicKey,
  packet : @packet.PublicKeyPacket,
  now : Int64,
) -> Bool raise {
  if key.is_revoked(now) {
    return false
  }
  if packet.key_id().equal(key.primary.key_id()) {
    return component_usable(
      key.primary,
      Some(key.self_signature()),
      FLAG_SIGN_OR_CERTIFY,
      now,
    )
  }
  for c in key.subkeys {
    if c.key.key_id().equal(packet.key_id()) {
      return !subkey_revoked_at(c.revocation, key.primary, c.key, now) &&
        component_usable(c.key, Some(c.binding), FLAG_SIGN_OR_CERTIFY, now)
    }
  }
  false
}

///|
/// Find an encryption-capable public key packet by 8-octet key id that is
/// still usable at `now` (lifecycle-checked: revocation, key flags and
/// expiry — a key without key flags counts as capable; `now = 0` skips
/// the time checks). All public-key algorithms participate; errors from
/// key-id computation propagate (F15): the keys were parsed on the way
/// in, so a failure here is an invariant violation, not a lookup miss.
pub fn KeyRing::find_encryption_key(
  self : KeyRing,
  key_id : BytesView,
  now~ : Int64 = 0L,
) -> @packet.PublicKeyPacket? raise {
  for key in self.public_keys {
    for p in all_public_packets(key) {
      let id = p.key_id()
      if id.equal(key_id.to_owned()) &&
        key_packet_encryption_usable_at(key, p, now) {
        return Some(p)
      }
    }
  }
  None
}

///|
/// Find the unlocked private key packet matching a PKESK key id.
/// Deliberately NOT lifecycle-gated: decrypting mail that arrived before
/// a key expired must keep working (mirrors gopenpgp, whose decryption
/// path does not check expiry either).
pub fn KeyRing::find_decryption_key(
  self : KeyRing,
  key_id : BytesView,
) -> @packet.SecretKeyPacket? raise {
  for key in self.private_keys {
    let candidates : Array[@packet.SecretKeyPacket] = [key.primary]
    for c in key.subkeys {
      candidates.push(c.secret)
    }
    for sk in candidates {
      let id = sk.public.key_id()
      if id.equal(key_id.to_owned()) && sk.s2k_usage == 0 {
        return Some(sk)
      }
    }
  }
  None
}

///|
/// Find a transferable key that can verify a signature from `key_id` and
/// is still usable at `now` (revocation, sign/certify flags, expiry).
pub fn KeyRing::find_verification_key(
  self : KeyRing,
  key_id : BytesView,
  now~ : Int64 = 0L,
) -> PublicKey? raise {
  for key in self.public_keys {
    for p in all_public_packets(key) {
      let id = p.key_id()
      if id.equal(key_id.to_owned()) && key_packet_verify_usable_at(key, p, now) {
        return Some(key)
      }
    }
  }
  None
}

///|
pub extend KeyRing with @moonbitlang/core/debug.Debug::{to_repr}
