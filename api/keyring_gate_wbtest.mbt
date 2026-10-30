///|
/// Ring-level gate tests, written as missing-capability differentials:
/// delete the lifecycle gate from `key_packet_*_usable_at`, revert the
/// per-packet subkey judgment, or drop the cross-certification check,
/// and one of these tests turns red. Direct `find_*` tests at `now = 0`
/// cannot catch a deleted gate (time checks are off there), so every
/// expiry differential runs both clock states against the same ring.

///|
fn with_key_expiration(
  binding : @packet.SignaturePacket,
  created : Int32,
  lifetime : Int32,
) -> @packet.SignaturePacket {
  let exp = created + lifetime
  {
    ..binding,
    hashed_subpackets: [
      ..binding.hashed_subpackets,
      {
        critical: false,
        sub_type: @packet.SIGSUB_KEY_EXPIRATION_TIME,
        body: Bytes::from_array([
          ((exp >> 24) & 0xFF).to_byte(),
          ((exp >> 16) & 0xFF).to_byte(),
          ((exp >> 8) & 0xFF).to_byte(),
          (exp & 0xFF).to_byte(),
        ]),
      },
    ],
  }
}

///|
test "ring encryption lookup judges the matched subkey's own lifetime" {
  let key = generate_key("X <x@example.com>", bits=2048)
  let created = key.subkeys[0].secret.public.creation_time
  let expired_binding = with_key_expiration(key.subkeys[0].binding, created, 60)
  let pk = {
    ..key,
    subkeys: [
      SecretSubkeyCert::{
        secret: key.subkeys[0].secret,
        binding: expired_binding,
        revocation: None,
      },
    ],
  }.to_public()
  let ring = KeyRing::new()
  // The differential pair: an expired component and a valid component
  // in one ring, looked up at a real clock. If the gate were deleted,
  // the expired id would resolve too and this test would fail.
  let fresh = generate_key("F <f@example.com>", bits=2048)
  ring.add_public(pk)
  ring.add_public(fresh.to_public())
  let expired_id = pk.subkeys[0].key.key_id()
  let fresh_id = fresh.to_public().subkeys[0].key.key_id()
  // now = 0 turns the time checks off: both resolve.
  assert_true(ring.find_encryption_key(expired_id) is Some(_))
  let now = @primitives.unix_now()
  if now != 0L {
    let later = now + 120L
    assert_true(ring.find_encryption_key(expired_id, now=later) is None)
    // The valid sibling key is still chosen at the same timestamp.
    assert_true(ring.find_encryption_key(fresh_id, now=later) is Some(_))
  }
}

///|
test "ring verification lookup judges the primary certification's lifetime" {
  let key = generate_ed25519_key("E <e@example.com>")
  let created = key.primary.public.creation_time
  let expired_self = with_key_expiration(
    key.user_ids[0].self_signature,
    created,
    60,
  )
  let pk : PublicKey = {
    ..key.to_public(),
    user_ids: [{ ..key.user_ids[0], self_signature: expired_self, }],
  }
  let ring = KeyRing::new()
  let fresh = generate_ed25519_key("G <g@example.com>")
  ring.add_public(pk)
  ring.add_public(fresh.to_public())
  let expired_id = pk.primary.key_id()
  let fresh_id = fresh.to_public().primary.key_id()
  assert_true(ring.find_verification_key(expired_id) is Some(_))
  let now = @primitives.unix_now()
  if now != 0L {
    let later = now + 120L
    assert_true(ring.find_verification_key(expired_id, now=later) is None)
    assert_true(ring.find_verification_key(fresh_id, now=later) is Some(_))
  }
}

///|
test "ring selection refuses a revoked key outright" {
  let key = generate_ed25519_key("R <r@example.com>")
  let revoked = revoke_key(key)
  let pub_half = revoked.to_public()
  let ring = KeyRing::new()
  ring.add_public(pub_half)
  // Revocation is cryptographically validated at any clock, `now = 0`
  // included: deleting the revocation check turns both lookups green.
  assert_true(ring.find_verification_key(pub_half.primary.key_id()) is None)
  assert_true(
    ring.find_encryption_key(pub_half.subkeys[0].key.key_id()) is None,
  )
}

///|
test "verification lookup judges the matched subkey, not its siblings" {
  let key = generate_ed25519_key("S <s@example.com>")
    .add_signing_subkey()
    .add_signing_subkey()
  let pk = key.to_public()
  // subkeys = [encryption, signing A, signing B]
  let a_id = pk.subkeys[1].key.key_id()
  let b_id = pk.subkeys[2].key.key_id()
  let revoked = revoke_subkey(key, a_id, reason=Retired)
  let ring = KeyRing::new()
  ring.add_public(revoked.to_public())
  // A signature issued by subkey A must not pass the gate because its
  // sibling B is healthy: the matched packet is judged by its own
  // binding. Reverting to the any-sibling rule turns the first assert
  // green and this test red.
  assert_true(ring.find_verification_key(a_id) is None)
  assert_true(ring.find_verification_key(b_id) is Some(_))
}

///|
fn strip_embedded_signatures(
  binding : @packet.SignaturePacket,
) -> @packet.SignaturePacket {
  let keep = fn(
    subs : Array[@packet.SigSubpacket],
  ) -> Array[@packet.SigSubpacket] {
    let out : Array[@packet.SigSubpacket] = []
    for sp in subs {
      if sp.sub_type != @packet.SIGSUB_EMBEDDED_SIGNATURE {
        out.push(sp)
      }
    }
    out
  }
  {
    ..binding,
    hashed_subpackets: keep(binding.hashed_subpackets),
    unhashed_subpackets: keep(binding.unhashed_subpackets),
  }
}

///|
test "a signing subkey without cross-certification is refused" {
  // The v6 dual-subkey shape: a cert-only primary, so signing must come
  // from the signing subkey, whose binding carries the cross-cert.
  let key = generate_ed25519_v6_key_with_signing_subkey("N <n@example.com>")
  // Control: the intact key signs (from the cross-certified subkey).
  let _ = sign_detached(b"control payload", key)
  // Strip the embedded Primary Key Binding from every subkey's binding:
  // the encryption subkey loses nothing it needed, the signing subkey
  // loses its cross-certification. In-memory only — the mutated binding
  // is no longer valid wire data.
  let stripped : PrivateKey = {
    ..key,
    subkeys: key.subkeys.map(fn(c) {
      { ..c, binding: strip_embedded_signatures(c.binding), }
    }),
  }
  let raised = try {
    let _ = sign_detached(b"uncrossed payload", stripped)
    false
  } catch {
    _ => true
  }
  // Deleting `subkey_cross_certified` from `signing_packet` turns this
  // assert false: the uncrossed subkey would issue a signature gpg
  // refuses to verify.
  assert_true(raised)
}
