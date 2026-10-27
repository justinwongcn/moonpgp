///|
/// User ID management for an existing certificate (RFC 9580 §10.1):
/// adding identities, revoking one, and naming the primary. All of these
/// re-sign with the primary key, so the key must be unlocked.

///|
/// Refresh the creation-time statement of a hashed subpacket area to
/// `now`, keeping every other statement in place.
fn hashed_with_refreshed_creation(
  hashed : Array[@packet.SigSubpacket],
  now : Int32,
) -> Array[@packet.SigSubpacket] {
  let out : Array[@packet.SigSubpacket] = []
  for s in hashed {
    if s.sub_type == @packet.SIGSUB_CREATION_TIME {
      out.push({ ..s, body: creation_subpacket(now).body, })
    } else {
      out.push(s)
    }
  }
  out
}

///|
/// Rebuild a hashed area with the Primary User ID flag set (RFC 9580
/// §5.2.3.20, one octet of 0x01), replacing any previous flag statement.
fn hashed_with_primary_flag(
  hashed : Array[@packet.SigSubpacket],
  now : Int32,
) -> Array[@packet.SigSubpacket] {
  let sp : @packet.SigSubpacket = {
    critical: false,
    sub_type: @packet.SIGSUB_PRIMARY_USER_ID,
    body: Bytes::from_array([1]),
  }
  let out : Array[@packet.SigSubpacket] = []
  let mut inserted = false
  for s in hashed {
    if s.sub_type == @packet.SIGSUB_PRIMARY_USER_ID {
      continue
    }
    if s.sub_type == @packet.SIGSUB_CREATION_TIME {
      out.push({ ..s, body: creation_subpacket(now).body, })
    } else {
      out.push(s)
    }
    if !inserted && s.sub_type == @packet.SIGSUB_CREATION_TIME {
      out.push(sp)
      inserted = true
    }
  }
  if !inserted {
    out.push(sp)
  }
  out
}

///|
/// Rebuild a hashed area without the Primary User ID flag — the
/// statement another User ID's certification just claimed.
fn hashed_without_primary_flag(
  hashed : Array[@packet.SigSubpacket],
  now : Int32,
) -> Array[@packet.SigSubpacket] {
  let out : Array[@packet.SigSubpacket] = []
  for s in hashed {
    if s.sub_type == @packet.SIGSUB_PRIMARY_USER_ID {
      continue
    }
    out.push(s)
  }
  hashed_with_refreshed_creation(out, now)
}

///|
/// The CertificationRevocation signature (type 0x30) by the primary key
/// over one of its own User IDs, with reason 32 "User ID no longer
/// valid" (RFC 9580 §5.2.3.31) and the optional message.
fn make_uid_revocation_signature(
  secret_packet : @packet.SecretKeyPacket,
  pub_packet : @packet.PublicKeyPacket,
  user_id : String,
  message : String?,
  now : Int32,
) -> @packet.SignaturePacket raise {
  let v6 = pub_packet.version() >= 6
  let hashed : Array[@packet.SigSubpacket] = [
    { ..creation_subpacket(now), critical: true, },
    {
      critical: false,
      sub_type: @packet.SIGSUB_REVOCATION_REASON,
      body: Bytes::from_array([32]).add(
        @primitives.utf8_bytes(message.unwrap_or("")),
      ),
    },
  ]
  if v6 {
    hashed.push(issuer_fingerprint_subpacket(pub_packet))
  }
  let unhashed : Array[@packet.SigSubpacket] = if v6 {
    []
  } else {
    [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: pub_packet.key_id(),
      },
    ]
  }
  let sig : @packet.SignaturePacket = {
    version: if v6 {
      6
    } else {
      4
    },
    sig_type: @packet.CertificationRevocation,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: if v6 {
      @primitives.random_bytes(
        @packet.salt_size_of_hash(@primitives.Sha256.number()),
      )
    } else {
      Bytes::new(0)
    },
    sig_params: [],
  }
  let digest = hash_certification(sig, pub_packet, user_id)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Return a copy of `key` with a new User ID certified by the primary
/// key — the "I also answer to this address" operation. The new
/// certification inherits the key flags of the key-level self-signature
/// so capability statements stay consistent across User IDs. The key
/// must be unlocked.
pub fn PrivateKey::add_user_id(
  self : PrivateKey,
  user_id : String,
  created? : Int32,
) -> PrivateKey raise {
  guard user_id != "" else { @error.fail("api: user id must not be empty") }
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let flags = governing_flags(Some(self.self_signature())).unwrap_or(0x03)
  let sig = make_self_signature(
    self.primary,
    self.primary.public,
    user_id,
    now,
    key_flags=flags,
  )
  let user_ids = self.user_ids.copy()
  user_ids.push(UserIdBinding::{
    user_id,
    self_signature: sig,
    revocation: None,
  })
  { ..self, user_ids, }
}

///|
/// Return a copy of `key` with the named User ID revoked: a
/// CertificationRevocation signature by the primary, attached to the
/// binding. The User ID stays on the certificate — the revocation is the
/// public statement that the identity is no longer valid (what gpg's
/// `--quick-revoke-uid` writes). Re-certifying the same User ID later is
/// `add_user_id`. The key must be unlocked.
pub fn PrivateKey::revoke_user_id(
  self : PrivateKey,
  user_id : String,
  message? : String,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let user_ids : Array[UserIdBinding] = []
  let mut found = false
  for b in self.user_ids {
    if !found && b.user_id == user_id {
      let sig = make_uid_revocation_signature(
        self.primary,
        self.primary.public,
        user_id,
        message,
        now,
      )
      user_ids.push({ ..b, revocation: Some(sig), })
      found = true
    } else {
      user_ids.push(b)
    }
  }
  guard found else { @error.fail("api: no user id \"\{user_id}\" on this key") }
  { ..self, user_ids, }
}

///|
/// Name `user_id` the certificate's primary identity: its certification
/// is re-issued with the Primary User ID flag (RFC 9580 §5.2.3.20) and
/// every other User ID loses the flag. `user_id()` then reports it.
/// The key must be unlocked.
pub fn PrivateKey::set_primary_user_id(
  self : PrivateKey,
  user_id : String,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let user_ids : Array[UserIdBinding] = []
  let mut found = false
  for b in self.user_ids {
    let hashed = if b.user_id == user_id {
      found = true
      hashed_with_primary_flag(b.self_signature.hashed_subpackets, now)
    } else {
      hashed_without_primary_flag(b.self_signature.hashed_subpackets, now)
    }
    let re = reissue_sig(b.self_signature, self.primary, hashed, s => {
      hash_certification(s, self.primary.public, b.user_id)
    })
    user_ids.push({ ..b, self_signature: re, })
  }
  guard found else { @error.fail("api: no user id \"\{user_id}\" on this key") }
  { ..self, user_ids, }
}

///|
/// True when the named User ID carries a cryptographically valid, already
/// effective CertificationRevocation — the lazy-verification model used
/// for key revocations (`is_revoked`): import attaches the signature, and
/// the cryptographic check happens here. `now = 0` disables the
/// effective-date question.
pub fn PublicKey::is_user_id_revoked(
  self : PublicKey,
  user_id : String,
  now : Int64,
) -> Bool {
  for b in self.user_ids {
    if b.user_id == user_id {
      match b.revocation {
        Some(s) => {
          let verified = verify_key_signature(
            s,
            self.primary,
            self.primary,
            user_id~,
          ) catch {
            _ => false
          }
          if verified && revocation_effective_at(s, now) {
            return true
          }
        }
        None => ()
      }
    }
  }
  false
}

///|
/// See `PublicKey::is_user_id_revoked`. Delegates to the public half.
pub fn PrivateKey::is_user_id_revoked(
  self : PrivateKey,
  user_id : String,
  now : Int64,
) -> Bool {
  self.to_public().is_user_id_revoked(user_id, now)
}
