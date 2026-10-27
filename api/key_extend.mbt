///|
/// Extending an existing certificate (RFC 9580 §10.1 transferable-key
/// surgery): adding subkeys to a key you hold, and setting, extending or
/// clearing expiry by re-issuing the governing self-signatures. All of
/// these re-sign, so the key must be unlocked — the same guard the
/// document-signing path enforces.
///
/// Re-issuance mechanics: the parsed signature's hashed statements are
/// carried over (minus the Key Expiration Time statement, which the new
/// one replaces, and any Signature Expiration, which bound the OLD
/// issuance only), the raw hashed area is dropped so the modified
/// subpacket list is what actually gets hashed (`to_body`/`hash_prefix`
/// prefer raw wire bytes whenever present), and the primary re-signs.

///|
/// The 4-octet Key Expiration Time subpacket body: seconds after the
/// key's creation time (0 = never expires).
fn key_expiration_body(seconds : Int64) -> Bytes raise {
  guard seconds >= 0 && seconds <= 0xFFFFFFFFL else {
    @error.fail("api: key lifetime must fit the 4-octet subpacket (0..2^32-1)")
  }
  Bytes::makei(4, i => ((seconds >> (24 - i * 8)) & 0xFFL).to_byte())
}

///|
/// Rebuild a hashed subpacket area with a fresh creation time and the
/// Key Expiration statement inserted right after it (gpg's ordering).
/// Signature Expiration statements are dropped: they bounded the old
/// issuance, and carrying one into a freshly created signature could
/// expire it immediately.
fn hashed_with_key_expiration(
  hashed : Array[@packet.SigSubpacket],
  seconds : Int64,
  now : Int32,
) -> Array[@packet.SigSubpacket] raise {
  let sp : @packet.SigSubpacket = {
    critical: false,
    sub_type: @packet.SIGSUB_KEY_EXPIRATION_TIME,
    body: key_expiration_body(seconds),
  }
  let out : Array[@packet.SigSubpacket] = []
  let mut inserted = false
  for s in hashed {
    if s.sub_type == @packet.SIGSUB_KEY_EXPIRATION_TIME ||
      s.sub_type == @packet.SIGSUB_SIG_EXPIRATION_TIME {
      continue
    }
    if s.sub_type == @packet.SIGSUB_CREATION_TIME {
      out.push({ ..s, body: creation_subpacket(now).body, })
      out.push(sp)
      inserted = true
    } else {
      out.push(s)
    }
  }
  if !inserted {
    out.push(sp)
  }
  out
}

///|
/// Re-issue a parsed signature over a modified hashed area and re-sign
/// it with `secret`; `digest_of` supplies the hash input for the
/// signature type (certification / direct key / binding). The raw hashed
/// area is dropped so the modified subpacket list is what gets hashed
/// (`to_body`/`hash_prefix` prefer raw wire bytes whenever present).
fn reissue_sig(
  sig : @packet.SignaturePacket,
  secret : @packet.SecretKeyPacket,
  hashed : Array[@packet.SigSubpacket],
  digest_of : (@packet.SignaturePacket) -> Bytes raise,
) -> @packet.SignaturePacket raise {
  let fresh : @packet.SignaturePacket = {
    ..sig,
    hashed_subpackets: hashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    sig_params: [],
  }
  let digest = digest_of(fresh)
  let hash_id = match @primitives.hash_id_of_number(fresh.hash_algo()) {
    Some(h) => h
    None =>
      @error.unsupported(
        "api: signature uses unknown hash algorithm \{fresh.hash_algo()}",
      )
  }
  finish_signature(fresh, secret, hash_id, digest.exact_view())
}

///|
/// Re-issue a parsed signature with new expiry statements and re-sign it
/// with `secret`.
fn resign_sig_with_expiry(
  sig : @packet.SignaturePacket,
  secret : @packet.SecretKeyPacket,
  seconds : Int64,
  now : Int32,
  digest_of : (@packet.SignaturePacket) -> Bytes raise,
) -> @packet.SignaturePacket raise {
  reissue_sig(
    sig,
    secret,
    hashed_with_key_expiration(sig.hashed_subpackets, seconds, now),
    digest_of,
  )
}

///|
/// Set (or extend, or clear with 0) the primary key's expiry: every
/// governing self-signature — each User ID certification plus the v6
/// Direct Key signature — is re-issued with a Key Expiration Time of
/// `seconds`. The lifetime counts from the KEY's creation time (RFC 9580
/// §5.2.3.6 semantics), so "30 days from key creation" stays 2592000 no
/// matter when the extension happens. The key must be unlocked.
///
/// # Example
///
/// ```mbt check
/// test "an expiry is visible through the lifecycle checks" {
///   let key = @api.generate_ed25519_key("E <e@example.com>").set_expiry(3600)
///   let now = @primitives.unix_now()
///   assert_false(key.is_expired(now))
///   assert_true(key.is_expired(now + 3601))
/// }
/// ```
pub fn PrivateKey::set_expiry(
  self : PrivateKey,
  seconds : Int64,
  created? : Int32,
) -> PrivateKey raise {
  guard self.user_ids.length() > 0 || self.direct_signature is Some(_) else {
    @error.fail("api: key has no self-signature to carry an expiry")
  }
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let user_ids : Array[UserIdBinding] = []
  for b in self.user_ids {
    let re = resign_sig_with_expiry(
      b.self_signature,
      self.primary,
      seconds,
      now,
      s => hash_certification(s, self.primary.public, b.user_id),
    )
    user_ids.push({ ..b, self_signature: re, })
  }
  let direct = match self.direct_signature {
    Some(d) =>
      Some(
        resign_sig_with_expiry(d, self.primary, seconds, now, s => {
          hash_direct_key(s, self.primary.public)
        }),
      )
    None => None
  }
  { ..self, user_ids, direct_signature: direct, }
}

///|
/// Set (or extend, or clear with 0) one subkey's expiry by re-issuing
/// its binding signature with a Key Expiration Time of `seconds` —
/// `gpg --quick-set-expire <fpr> <subkey-fpr>`. The subkey is matched by
/// key id; an embedded cross-certification rides in the unhashed area
/// and survives untouched. The key must be unlocked.
pub fn PrivateKey::set_subkey_expiry(
  self : PrivateKey,
  subkey_id : BytesView,
  seconds : Int64,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let subkeys : Array[SecretSubkeyCert] = []
  let mut found = false
  for c in self.subkeys {
    let id = c.secret.public.key_id() catch { _ => Bytes::new(0) }
    if !found && id.length() > 0 && id.equal(subkey_id.to_owned()) {
      let binding = resign_sig_with_expiry(
        c.binding,
        self.primary,
        seconds,
        now,
        s => hash_binding(s, self.primary.public, c.secret.public),
      )
      subkeys.push({ ..c, binding, })
      found = true
    } else {
      subkeys.push(c)
    }
  }
  guard found else {
    @error.fail("api: no subkey of this key matches the given key id")
  }
  { ..self, subkeys, }
}

///|
/// Generate a fresh encryption subkey (Curve25519Legacy ECDH on a v4
/// key, native X25519 on a v6 one) and bind it to this key — the
/// rotation story for an expiring or compromised encryption subkey.
/// The key must be unlocked. Wire order places the new subkey last,
/// which is the one `encryption_key` prefers.
pub fn PrivateKey::add_encryption_subkey(
  self : PrivateKey,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let subkey = if self.primary.public.version() >= 6 {
    build_v6_x25519_secret_key_packet(now)
  } else {
    build_ecdh_secret_key_packet(now)
  }
  let binding = make_binding_signature(
    self.primary,
    self.primary.public,
    subkey.public,
    now,
  )
  let subkeys = self.subkeys.copy()
  subkeys.push(SecretSubkeyCert::{ secret: subkey, binding, revocation: None, })
  { ..self, subkeys, }
}

///|
/// Generate a fresh signing subkey (EdDSA legacy on a v4 key, native
/// Ed25519 on a v6 one) and bind it with the cross-certification gpg
/// requires (RFC 9580 §5.2.3.26) — the rotation story for a signing
/// subkey. The key must be unlocked.
pub fn PrivateKey::add_signing_subkey(
  self : PrivateKey,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let subkey = if self.primary.public.version() >= 6 {
    build_ed25519_v6_secret_key_packet(@primitives.random_bytes(32), now)
  } else {
    build_eddsa_secret_key_packet(@primitives.random_bytes(32), now)
  }
  let binding = make_binding_signature(
    self.primary,
    self.primary.public,
    subkey.public,
    now,
    key_flags=0x02,
    subkey_secret=subkey,
  )
  let subkeys = self.subkeys.copy()
  subkeys.push(SecretSubkeyCert::{ secret: subkey, binding, revocation: None, })
  { ..self, subkeys, }
}
