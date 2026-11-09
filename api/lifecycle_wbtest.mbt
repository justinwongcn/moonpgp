///|
/// M1 lifecycle tests: expiry/revocation/capability semantics on keys
/// generated in-process (whitebox: they mutate transferable-key structs
/// directly). Fixture-based lifecycle tests (expired and revoked gopenpgp
/// keys, deterministic fixed timestamps) live in
/// `interop/lifecycle_test.mbt`.

///|
test "a fresh key is alive and capable" {
  let key = generate_key("Life <life@example.com>", bits=2048)
  // now = 0 disables the time checks entirely.
  assert_false(key.is_expired(0L))
  assert_false(key.is_revoked(0L))
  assert_true(key.can_encrypt(0L))
  assert_true(key.can_verify(0L))
  let now = @primitives.unix_now()
  assert_false(key.is_expired(now))
  assert_false(key.is_revoked(now))
  assert_true(key.can_encrypt(now))
  assert_true(key.can_verify(now))
}

///|
test "v4 Ed25519 and v6 keys are alive and capable" {
  let ed = generate_ed25519_key("Ed <ed@example.com>")
  let now = @primitives.unix_now()
  assert_true(ed.can_encrypt(now))
  assert_true(ed.can_verify(now))
  let v6 = generate_ed25519_v6_key("V6 <v6@example.com>")
  assert_true(v6.can_encrypt(now))
  assert_true(v6.can_verify(now))
  assert_false(v6.is_revoked(now))
  assert_false(v6.is_expired(now))
}

///|
test "a far-future timestamp expires nothing that has no lifetime" {
  // Generated keys carry no Key Expiration Time and no Signature
  // Expiration Time, so even an absurdly late `now` finds nothing expired.
  let key = generate_key("Eternal <e@example.com>", bits=2048)
  assert_false(key.is_expired(4_102_444_800L)) // 2100-01-01
  assert_true(key.can_encrypt(4_102_444_800L))
}

///|
test "tampered user id fails import (certification must verify)" {
  let key = generate_key("Honest <h@example.com>", bits=2048)
  let tampered : PrivateKey = {
    ..key,
    user_ids: [
      UserIdBinding::{
        user_id: "Eve <eve@example.net>",
        self_signature: key.self_signature(),
        revocation: None,
      },
    ],
  }
  let raised = try {
    let _ = PrivateKey::from_bytes(tampered.to_bytes().exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "swapped subkey fails import (binding must verify)" {
  let key = generate_key("A <a@example.com>", bits=2048)
  let other = generate_key("B <b@example.com>", bits=2048)
  // Another key's subkey under this key's binding: the binding does not
  // cover the foreign material, so import must reject it.
  let mixed : PrivateKey = {
    ..key,
    subkeys: [
      SecretSubkeyCert::{
        secret: other.subkeys[0].secret,
        binding: key.subkeys[0].binding,
        revocation: None,
      },
    ],
  }
  let raised = try {
    let _ = PrivateKey::from_bytes(mixed.to_bytes().exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "swapped v6 direct-key signature fails import" {
  let key = generate_ed25519_v6_key("K <k@example.com>")
  let other = generate_ed25519_v6_key("O <o@example.com>")
  let mixed : PrivateKey = { ..key, direct_signature: other.direct_signature, }
  let raised = try {
    let _ = PrivateKey::from_bytes(mixed.to_bytes().exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "keyring finds non-RSA encryption subkeys (previously is_rsa-gated)" {
  let ed = generate_ed25519_key("Ed <ed@example.com>")
  let ring = KeyRing::new()
  ring.add_public(ed.to_public())
  let sub_id = ed.to_public().subkeys[0].key.key_id()
  assert_true(ring.find_encryption_key(sub_id) is Some(_))
  let v6 = generate_ed25519_v6_key("V6 <v6@example.com>")
  ring.add_public(v6.to_public())
  let v6_sub = v6.to_public().subkeys[0].key.key_id()
  assert_true(ring.find_encryption_key(v6_sub) is Some(_))
  // The primary (EdDSA) is not encryption-capable and must not resolve.
  assert_true(ring.find_encryption_key(v6.key_id()) is None)
}

///|
test "expired subkey binding drops the subkey from encryption selection" {
  // Mutate an existing binding in memory to carry a Key Expiration Time of
  // 60 seconds — RFC 9580 §5.2.3.13 semantics (seconds after the subkey's
  // creation; an earlier draft stamped the absolute expiry date here, and
  // the assertion only held through the Int32 wrap S1 removed). Not
  // re-imported: the signature is no longer valid wire data once its
  // hashed area changed.
  let key = generate_key("X <x@example.com>", bits=2048)
  let old = key.subkeys[0].binding
  let expired_binding = with_key_expiration(old, 60)
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
  let now = @primitives.unix_now()
  if now != 0L {
    // Past its binding's lifetime the subkey drops out of selection; the
    // RSA primary is certify+sign only (flags 0x03), so nothing on the
    // key may encrypt any more.
    let later = now + 120
    assert_false(pk.can_encrypt(later))
    assert_true(pk.encryption_packet_at(later) is None)
    // Verification is unaffected by the subkey's expiry.
    assert_true(pk.can_verify(later))
  }
  // now = 0 turns the time checks off and the subkey is selected again.
  assert_true(pk.encryption_packet_at(0L) is Some(_))
}

///|
test "a swapped certification fails import on a multi-uid key" {
  // Build a two-User-ID key where the second User ID is certified with
  // the FIRST User ID's certification: the signature does not cover that
  // User ID, so strict import rejects (M5 × M1 composition).
  let key = generate_key("Real <real@example.com>", bits=2048)
  let forged_binding : UserIdBinding = {
    user_id: "Forged <forged@example.net>",
    self_signature: key.self_signature(),
    revocation: None,
  }
  let mixed : PrivateKey = {
    ..key,
    user_ids: [key.user_ids[0], forged_binding],
  }
  let raised = try {
    let _ = PrivateKey::from_bytes(mixed.to_bytes().exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "a generated key exposes one binding and stable accessors" {
  let key = generate_key("Solo <solo@example.com>", bits=2048)
  assert_eq(key.user_ids.length(), 1)
  assert_eq(key.user_id(), "Solo <solo@example.com>")
  assert_true(
    verify_key_signature(
      key.self_signature(),
      key.primary.public,
      key.primary.public,
      user_id=key.user_id(),
    ),
  )
  // Round trip keeps the bindings byte-stable.
  let again = PrivateKey::from_bytes(key.to_bytes().exact_view())
  assert_eq(again.user_ids.length(), 1)
  assert_eq(again.user_ids[0].user_id, "Solo <solo@example.com>")
  assert_eq(again.to_bytes(), key.to_bytes())
}

///|
/// A key whose primary packet was created 2 h ago with a 1 h lifetime:
/// the primary expired an hour ago while the encryption subkey carries no
/// Key Expiration Time at all. In-memory only — the shifted primary no
/// longer re-verifies over its certifications, which the lifecycle gates
/// never do (import already did).
fn with_expired_primary(key : PrivateKey, now : Int64) -> PublicKey {
  let created = (now - 7200L).to_int()
  let expired_self = with_key_expiration(key.user_ids[0].self_signature, 3600)
  {
    ..key.to_public(),
    primary: { ..key.primary.public, creation_time: created, },
    user_ids: [{ ..key.user_ids[0], self_signature: expired_self, }],
  }
}

///|
test "an expired primary drops the live encryption subkey from selection" {
  // The acceptance-review bug: the primary expired an hour ago, the
  // encryption subkey is still inside its own validity, and encryption
  // went through anyway. An expired primary invalidates every component
  // (N7 symmetry with the verify path).
  let key = generate_ed25519_key("EP <ep@example.com>")
  let now = @primitives.unix_now()
  if now != 0L {
    let pk = with_expired_primary(key, now)
    assert_true(pk.is_expired(now))
    assert_false(pk.can_encrypt(now))
    assert_true(pk.encryption_packet_at(now) is None)
    assert_false(pk.can_verify(now))
    // End-to-end: the real-clock seal path hits the same gate.
    let raised = try {
      let _ = encrypt_to_recipients(b"payload", [pk])
      false
    } catch {
      _ => true
    }
    assert_true(raised)
  }
}

///|
test "long legal lifetimes do not wrap into instant expiry" {
  // u32_secs: a lifetime whose absolute expiry crosses 2038 used to wrap
  // the Int32 sum negative and expire the key at creation. 5e8 s from a
  // 2026 creation lands in 2042 and must be honoured (the writer allows
  // up to 2^32-1).
  let key = generate_ed25519_key("LT <lt@example.com>").set_expiry(500_000_000)
  let now = @primitives.unix_now()
  if now != 0L {
    assert_false(key.is_expired(now))
    assert_true(key.is_expired(now + 500_000_001L))
    // The 4-octet wire value round-trips: the exported certificate judges
    // the same way.
    let again = PrivateKey::from_armored(key.to_armored())
    assert_false(again.is_expired(now))
    assert_true(again.is_expired(now + 500_000_001L))
  }
}

///|
test "a lifetime of 2^31 seconds reads back unsigned, not negative" {
  // Wire value 0x80000000 parses as Int32 -2147483648 (F09); the expiry
  // arithmetic must treat it as 2147483648 s (≈68 years), not a stamp in
  // 1979 that expired before the key was made.
  let key = generate_ed25519_key("W32 <w@example.com>").set_expiry(
    2_147_483_648,
  )
  let now = @primitives.unix_now()
  if now != 0L {
    assert_false(key.is_expired(now))
    assert_true(key.is_expired(now + 2_147_483_649L))
  }
}

///|
test "a post-2038 future revocation is dormant until its stamp" {
  // revocation_effective_at used to compare the two's-complement Int32
  // creation stamp: u32 0xFFFFFFFF (2106-02-07) arrived as -1 and every
  // real clock passed `created <= now`, firing the revocation 80 years
  // early. Unsigned comparison keeps it dormant.
  let key = generate_ed25519_key("FR <fr@example.com>")
  let future = {
    ..key.user_ids[0].self_signature,
    hashed_subpackets: [creation_subpacket(-1)],
  }
  let now = @primitives.unix_now()
  if now != 0L {
    assert_false(revocation_effective_at(future, now))
  }
  assert_true(revocation_effective_at(future, 4_294_967_296L))
}

///|
test "an expired primary binds can_verify through a signing subkey" {
  // can_verify's subkey branch judged only the subkey's own binding, so a
  // healthy signing subkey verified under an expired primary. The gate now
  // sits on the certificate as a whole.
  let key = generate_ed25519_key("CV <cv@example.com>").add_signing_subkey()
  let now = @primitives.unix_now()
  if now != 0L {
    let pk = with_expired_primary(key, now)
    assert_true(pk.is_expired(now))
    assert_false(pk.can_verify(now))
    // A live primary with the same shape still verifies from the subkey.
    assert_true(key.to_public().can_verify(now))
  }
}
