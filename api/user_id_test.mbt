///|
/// User ID management: adding identities to an existing certificate,
/// revoking one, and naming the primary. Round-trips through the armored
/// import path prove the wire shape is well-formed and every re-issued
/// certification verifies.

///|
test "add_user_id: the key answers to two identities" {
  let key = @api.generate_ed25519_key("First <first@example.com>").add_user_id(
    "Second <second@example.com>",
  )
  assert_eq(key.user_id(), "First <first@example.com>")
  // Import cryptographically validates the new certification.
  let re = @api.PrivateKey::from_armored(key.to_armored())
  let pubk = re.to_public()
  assert_eq(pubk.user_ids.length(), 2)
  assert_eq(pubk.user_ids[1].user_id, "Second <second@example.com>")
  // Messages to the key, and signatures from it, are unaffected.
  let msg = b"for both identities"
  let armored = @api.encrypt_to_recipients(msg, [pubk])
  assert_eq(@api.decrypt_with_private_key(armored, re), msg)
  let sig = @api.sign_detached(b"x", re)
  assert_eq(@api.verify_detached(b"x", sig, pubk), @api.VerifyStatus::Ok)
}

///|
test "set_primary_user_id: user_id() follows the flag" {
  let key = @api.generate_ed25519_key("First <first@example.com>")
    .add_user_id("Second <second@example.com>")
    .set_primary_user_id("Second <second@example.com>")
  assert_eq(key.user_id(), "Second <second@example.com>")
  // The flag round-trips and only one User ID carries it.
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_eq(re.user_id(), "Second <second@example.com>")
  let flagged = re.user_ids
    .iter()
    .filter(fn(b) { b.self_signature.is_primary_user_id() })
    .collect()
  assert_eq(flagged.length(), 1)
  assert_eq(flagged[0].user_id, "Second <second@example.com>")
}

///|
test "revoke_user_id: the identity is publicly invalid, verifiably" {
  let key = @api.generate_ed25519_key("First <first@example.com>")
    .add_user_id("Burned <burned@example.com>")
    .revoke_user_id("Burned <burned@example.com>", message="address retired")
  // The User ID stays on the certificate with its revocation attached.
  let binding = key.user_ids
    .iter()
    .filter(fn(b) { b.user_id == "Burned <burned@example.com>" })
    .collect()[0]
  assert_true(binding.revocation is Some(_))
  assert_true(key.is_user_id_revoked("Burned <burned@example.com>", 0L))
  // The other identity is untouched.
  assert_false(key.is_user_id_revoked("First <first@example.com>", 0L))
  // The revocation is the primary's own signature: it verifies lazily
  // through the same path imported revocations take.
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_true(re.is_user_id_revoked("Burned <burned@example.com>", 0L))
  // An unrevoked alias still verifies signatures and receives mail.
  let pubk = re.to_public()
  assert_eq(
    @api.verify_detached(b"x", @api.sign_detached(b"x", re), pubk),
    @api.VerifyStatus::Ok,
  )
  assert_eq(
    @api.decrypt_with_private_key(@api.encrypt_to_recipients(b"m", [pubk]), re),
    b"m",
  )
}

///|
test "user id operations reject unknown names and empty ids" {
  let key = @api.generate_ed25519_key("A <a@example.com>")
  let raised = try {
    let _ = key.revoke_user_id("Nope <n@example.com>")
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("no user id"))
      true
    }
  }
  assert_true(raised)
  let raised2 = try {
    let _ = key.set_primary_user_id("Nope <n@example.com>")
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
  let raised3 = try {
    let _ = key.add_user_id("")
    false
  } catch {
    _ => true
  }
  assert_true(raised3)
}

///|
test "user id operations require an unlocked key" {
  let locked = @api.generate_ed25519_key("L <l@example.com>").lock("pw")
  let raised = try {
    let _ = locked.add_user_id("N <n@example.com>")
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("unlock"))
      true
    }
  }
  assert_true(raised)
}

///|
test "revoked user id survives a gpg-shaped re-import" {
  // A CertificationRevocation between the certification and the next
  // User ID must attach to the right identity on import, not vanish.
  let key = @api.generate_ed25519_key("One <one@example.com>")
    .add_user_id("Two <two@example.com>")
    .add_user_id("Three <three@example.com>")
    .revoke_user_id("Two <two@example.com>")
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_eq(re.user_ids.length(), 3)
  assert_true(re.is_user_id_revoked("Two <two@example.com>", 0L))
  assert_false(re.is_user_id_revoked("Three <three@example.com>", 0L))
}

///|
test "v6 user id operations round-trip with the created stamps" {
  let key = @api.generate_ed25519_v6_key("V6 <v6@example.com>")
    .add_user_id("Alt6 <alt6@example.com>", created=1700000010)
    .revoke_user_id(
      "Alt6 <alt6@example.com>",
      message="gone",
      created=1700000011,
    )
    .set_primary_user_id("V6 <v6@example.com>", created=1700000012)
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_true(re.is_user_id_revoked("Alt6 <alt6@example.com>", 0L))
  assert_false(re.is_user_id_revoked("V6 <v6@example.com>", 0L))
  assert_eq(re.user_id(), "V6 <v6@example.com>")
  // The explicit creation stamps survived the v6 signature shapes: the
  // revocation keeps its own stamp, and the final set_primary_user_id
  // re-issued every certification with ITS stamp (re-issuance refreshes
  // the creation time — that is the documented mechanic).
  let alt = re.user_ids
    .iter()
    .filter(fn(b) { b.user_id == "Alt6 <alt6@example.com>" })
    .collect()[0]
  assert_eq(alt.self_signature.creation_time(), Some(1700000012))
  let rev = alt.revocation.unwrap()
  assert_eq(rev.creation_time(), Some(1700000011))
}

///|
test "re-certifying a revoked user id restores the identity" {
  let key = @api.generate_ed25519_key("P <p@example.com>")
    .add_user_id("Temp <temp@example.com>")
    .revoke_user_id("Temp <temp@example.com>")
  // Re-certification replaces the binding outright (last certification
  // wins, exactly like import), so the identity is usable again — the
  // new certification is a fresh statement, and in-memory state matches
  // what a round trip produces.
  let revived = key.add_user_id("Temp <temp@example.com>")
  let re = @api.PrivateKey::from_armored(revived.to_armored())
  let bindings = re.user_ids
    .iter()
    .filter(fn(b) { b.user_id == "Temp <temp@example.com>" })
    .collect()
  assert_eq(bindings.length(), 1)
  assert_true(bindings[0].revocation is None)
  assert_false(re.is_user_id_revoked("Temp <temp@example.com>", 0L))
  // The in-memory copy agrees with the round trip.
  assert_false(revived.is_user_id_revoked("Temp <temp@example.com>", 0L))
}

///|
test "set_primary_user_id moves the flag and tolerates repetition" {
  // First move pins the flag on Two; moving it back strips Two's flag
  // (the strip path), and re-naming the already-primary identity must be
  // idempotent (the deduplication path) rather than stacking flags.
  let key = @api.generate_ed25519_key("One <one@example.com>")
    .add_user_id("Two <two@example.com>")
    .set_primary_user_id("Two <two@example.com>", created=1700000020)
    .set_primary_user_id("One <one@example.com>", created=1700000021)
    .set_primary_user_id("One <one@example.com>", created=1700000022)
  assert_eq(key.user_id(), "One <one@example.com>")
  let re = @api.PrivateKey::from_armored(key.to_armored())
  let flagged = re.user_ids
    .iter()
    .filter(fn(b) { b.self_signature.is_primary_user_id() })
    .collect()
  assert_eq(flagged.length(), 1)
  assert_eq(flagged[0].user_id, "One <one@example.com>")
  assert_eq(flagged[0].self_signature.creation_time(), Some(1700000022))
}
