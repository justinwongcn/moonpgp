///|
/// A collection of public and private keys with id lookup, mirroring the
/// gopenpgp KeyRing role.
pub struct KeyRing {
  priv public_keys : Array[PublicKey]
  priv private_keys : Array[PrivateKey]
} derive(Debug)

///|
pub fn KeyRing::new() -> KeyRing {
  KeyRing::{ public_keys: [], private_keys: [], }
}

///|
pub fn KeyRing::add_public(self : KeyRing, key : PublicKey) -> Unit {
  self.public_keys.push(key)
}

///|
pub fn KeyRing::add_private(self : KeyRing, key : PrivateKey) -> Unit {
  self.private_keys.push(key)
}

///|
pub fn KeyRing::public_count(self : KeyRing) -> Int {
  self.public_keys.length()
}

///|
pub fn KeyRing::private_count(self : KeyRing) -> Int {
  self.private_keys.length()
}

///|
/// All public key packets (primary + subkey) of a key, with their packets.
fn all_public_packets(key : PublicKey) -> Array[@packet.PublicKeyPacket] {
  let out = [key.primary]
  match key.encryption_subkey {
    Some(sk) => out.push(sk)
    None => ()
  }
  out
}

///|
/// Find an encryption-capable public key by 8-octet key id.
pub fn KeyRing::find_encryption_key(
  self : KeyRing,
  key_id : BytesView,
) -> @packet.PublicKeyPacket? {
  for key in self.public_keys {
    for p in all_public_packets(key) {
      try {
        let id = p.key_id()
        if id.equal(key_id.to_owned()) && p.algo().is_rsa() {
          return Some(p)
        }
      } catch {
        _ => ()
      }
    }
  }
  None
}

///|
/// Find the unlocked private key packet matching a PKESK key id.
pub fn KeyRing::find_decryption_key(
  self : KeyRing,
  key_id : BytesView,
) -> @packet.SecretKeyPacket? {
  for key in self.private_keys {
    let candidates = [key.primary]
    match key.encryption_subkey {
      Some(sk) => candidates.push(sk)
      None => ()
    }
    for sk in candidates {
      try {
        let id = sk.public.key_id()
        if id.equal(key_id.to_owned()) && !(sk.s2k_usage != 0) {
          return Some(sk)
        }
      } catch {
        _ => ()
      }
    }
  }
  None
}

///|
/// Find a public key that can verify a signature from `key_id` (returns
/// the owning transferable key).
pub fn KeyRing::find_verification_key(
  self : KeyRing,
  key_id : BytesView,
) -> PublicKey? {
  for key in self.public_keys {
    for p in all_public_packets(key) {
      try {
        let id = p.key_id()
        if id.equal(key_id.to_owned()) {
          return Some(key)
        }
      } catch {
        _ => ()
      }
    }
  }
  None
}

///|
pub extend KeyRing with @moonbitlang/core/debug.Debug::{to_repr}
