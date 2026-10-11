///|
/// M1 lifecycle tests: expiry/revocation/capability semantics on keys
/// generated in-process (whitebox: they mutate transferable-key structs
/// directly). Fixture-based lifecycle tests (expired and revoked gopenpgp
/// keys, deterministic fixed timestamps) live in
/// `interop/lifecycle_test.mbt`.

///|
test "a fresh key is alive and capable" {
  let key = generate_key("Life <life@example.com>", bits=1024)
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
  let key = generate_key("Eternal <e@example.com>", bits=1024)
  assert_false(key.is_expired(4_102_444_800L)) // 2100-01-01
  assert_true(key.can_encrypt(4_102_444_800L))
}

///|
test "tampered user id fails import (certification must verify)" {
  let key = generate_key("Honest <h@example.com>", bits=1024)
  let tampered : PrivateKey = {
    ..key,
    user_ids: [
      UserIdBinding::{
        user_id: "Eve <eve@example.net>",
        self_signature: key.self_signature(),
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
  let key = generate_key("A <a@example.com>", bits=1024)
  let other = generate_key("B <b@example.com>", bits=1024)
  let mixed : PrivateKey = {
    ..key,
    encryption_subkey: other.encryption_subkey,
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
  let sub_id = ed.to_public().encryption_subkey.unwrap().key_id()
  assert_true(ring.find_encryption_key(sub_id) is Some(_))
  let v6 = generate_ed25519_v6_key("V6 <v6@example.com>")
  ring.add_public(v6.to_public())
  let v6_sub = v6.to_public().encryption_subkey.unwrap().key_id()
  assert_true(ring.find_encryption_key(v6_sub) is Some(_))
  // The primary (EdDSA) is not encryption-capable and must not resolve.
  assert_true(ring.find_encryption_key(v6.key_id()) is None)
}

///|
test "expired subkey binding drops the subkey from encryption selection" {
  // Mutate an existing binding in memory to carry a Key Expiration Time
  // 60 s after the subkey's creation. (Not re-imported: the signature is
  // no longer valid wire data once its hashed area changed.)
  let key = generate_key("X <x@example.com>", bits=1024)
  let created = key.encryption_subkey.unwrap().public.creation_time
  let exp = created + 60
  let expired_binding : @packet.SignaturePacket = {
    ..key.subkey_binding.unwrap(),
    hashed_subpackets: [
      ..key.subkey_binding.unwrap().hashed_subpackets,
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
  let pk = { ..key, subkey_binding: Some(expired_binding), }.to_public()
  let now = @primitives.unix_now()
  if now != 0L {
    // Past its binding's lifetime the subkey drops out of selection; the
    // RSA primary is certify+sign only (flags 0x03), so nothing on the
    // key may encrypt any more.
    assert_false(pk.can_encrypt(now))
    assert_true(pk.encryption_packet_at(now) is None)
    // Verification is unaffected by the subkey's expiry.
    assert_true(pk.can_verify(now))
  }
  // now = 0 turns the time checks off and the subkey is selected again.
  assert_true(pk.encryption_packet_at(0L) is Some(_))
}

///|
test "a swapped certification fails import on a multi-uid key" {
  // Build a two-User-ID key where the second User ID is certified with
  // the FIRST User ID's certification: the signature does not cover that
  // User ID, so strict import rejects (M5 × M1 composition).
  let key = generate_key("Real <real@example.com>", bits=1024)
  let forged_binding : UserIdBinding = {
    user_id: "Forged <forged@example.net>",
    self_signature: key.self_signature(),
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
  let key = generate_key("Solo <solo@example.com>", bits=1024)
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
