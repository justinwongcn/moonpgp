///|
/// M1 lifecycle tests against gopenpgp's expired/revoked key fixtures,
/// with FIXED timestamps so the assertions are identical on every target
/// (the wall-clock paths are exercised in `api/lifecycle_test.mbt`).

///|
/// gopenpgp `testdata/key_expiredKey`: an RSA key whose Generic
/// certification carries a Signature Expiration Time of 1320 s counted
/// from creation time 1 — the *signature* is what expired (the key packet
/// itself has no Key Expiration Time).
test "expired certification disables capabilities at a fixed now" {
  let key = @api.PrivateKey::from_armored(read_testdata("key_expiredKey"))
  // Strict import (M1) still accepts the key: the certification verifies
  // cryptographically — expiry is a lifecycle question, not an import one.
  // The fixture is a primary-only key with certify+sign flags (0x03), so
  // it can never encrypt; the certification's Signature Expiration Time
  // (1337 s from creation 1; gpg rounds to "0h22m") is what kills
  // verification.
  let just_before = 1338L // created(1) + 1337: the last live second
  assert_false(key.is_expired(just_before)) // key-level lifetime unset
  assert_false(key.can_encrypt(just_before)) // flags 0x03, no subkey
  assert_true(key.can_verify(just_before))
  let just_after = 1339L
  assert_false(key.can_verify(just_after))
  // now = 0 disables the time checks entirely.
  assert_true(key.can_verify(0L))
}

///|
/// gopenpgp `testdata/key_revoked`: an RSA key with a Key Revocation
/// (0x20) "Revoked for fun" created 1622219968, plus a v4 subkey. The
/// revocation must verify cryptographically before it bites.
test "revoked key is detected at a fixed now and refuses encryption" {
  let key = @api.PublicKey::from_armored(read_testdata("key_revoked"))
  let before = 1_600_000_000L // 2020-09: revocation not yet effective
  assert_false(key.is_revoked(before))
  assert_true(key.can_encrypt(before))
  let after = 1_700_000_000L // 2023-11: well after the revocation
  assert_true(key.is_revoked(after))
  assert_false(key.can_encrypt(after))
  assert_false(key.can_verify(after))
  // now = 0 validates the revocation but ignores effective dates.
  assert_true(key.is_revoked(0L))
}

///|
test "encrypting to a revoked recipient is refused" {
  let revoked = @api.PublicKey::from_armored(read_testdata("key_revoked"))
  let healthy = @api.generate_key("H <h@example.com>", bits=2048)
  let raised = try {
    let _ = @api.encrypt_to_recipients(@primitives.utf8_bytes("x"), [revoked])
    false
  } catch {
    _ => true
  }
  // Revocation needs no wall clock — the gate fires on every target.
  // (Expiry gating is the clock-dependent half; it degrades to structural
  // rules on the clockless targets, see @api/lifecycle.mbt.)
  assert_true(raised)
  ignore(healthy)
}

///|
test "decrypting stays available for a key past its certification lifetime" {
  // The holder of a stale key can still read old mail: the decryption
  // path is deliberately not lifecycle-gated (mirrors gopenpgp).
  let key = @api.PrivateKey::from_armored(read_testdata("key_expiredKey"))
  let ring = @api.KeyRing::new()
  ring.add_private(key)
  assert_true(ring.find_decryption_key(key.key_id()) is Some(_))
}
