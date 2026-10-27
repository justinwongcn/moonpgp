///|
/// Extending an existing certificate: subkey rotation and expiry
/// management. Every test round-trips through the armored import path,
/// because import cryptographically validates every signature the
/// re-issuance touched.

///|
test "add_encryption_subkey: rotation keeps old mail readable" {
  let key = @api.generate_ed25519_key("R <r@example.com>")
  let msg = b"rotate me"
  // Mail encrypted to the original subkey must keep opening after the
  // rotation — adding a subkey never orphans the old ones.
  let before = @api.encrypt_to_recipients(msg, [key.to_public()])
  let rotated = key.add_encryption_subkey(created=1700000004)
  assert_eq(rotated.subkeys.length(), 2)
  // The created stamp landed on the new binding.
  assert_eq(rotated.subkeys[1].binding.creation_time(), Some(1700000004))
  assert_eq(@api.decrypt_with_private_key(before, rotated), msg)
  // New mail goes to the newest subkey (last in wire order) and decrypts.
  let after = @api.encrypt_to_recipients(msg, [rotated.to_public()])
  assert_eq(@api.decrypt_with_private_key(after, rotated), msg)
  // Import validates the new binding cryptographically.
  let re = @api.PrivateKey::from_armored(rotated.to_armored())
  assert_eq(re.subkeys.length(), 2)
}

///|
test "add_encryption_subkey: v6 key gets a v6 X25519 subkey" {
  let key = @api.generate_ed25519_v6_key("R6 <r6@example.com>")
  let rotated = key.add_encryption_subkey()
  assert_eq(rotated.subkeys.length(), 2)
  let msg = b"v6 rotation"
  let armored = @api.encrypt_to_recipients(msg, [rotated.to_public()])
  assert_eq(@api.decrypt_with_private_key(armored, rotated), msg)
  let re = @api.PrivateKey::from_armored(rotated.to_armored())
  assert_eq(re.subkeys.length(), 2)
}

///|
test "add_signing_subkey: binding carries a verifying cross-certification" {
  let key = @api.generate_ed25519_key("S <s@example.com>").add_signing_subkey()
  let re = @api.PrivateKey::from_armored(key.to_armored())
  let pubk = re.to_public()
  let sign_sub = pubk.subkeys[1]
  // The embedded Primary Key Binding (RFC 9580 §5.2.3.26) must verify as
  // the subkey's own signature over the primary — what gpg checks before
  // trusting anything the subkey signs.
  let body = @packet.find_subpacket(
    sign_sub.binding.unhashed_subpackets,
    @packet.SIGSUB_EMBEDDED_SIGNATURE,
  )
  let embedded = @packet.SignaturePacket::parse(body.unwrap().exact_view())
  assert_true(@api.verify_key_signature(embedded, sign_sub.key, pubk.primary))
}

///|
test "set_expiry: the key expires, then unexpires when cleared" {
  let key = @api.generate_ed25519_key("E <e@example.com>").set_expiry(3600)
  let now = @primitives.unix_now()
  assert_false(key.is_expired(now))
  assert_true(key.is_expired(now + 3601))
  let cleared = key.set_expiry(0)
  assert_false(cleared.is_expired(now + 3601))
  // The re-issued self-signature round-trips with the expiry attached.
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_true(re.is_expired(now + 3601))
}

///|
test "set_expiry: v6 direct-key signature is re-issued too" {
  let key = @api.generate_ed25519_v6_key("V <v@example.com>").set_expiry(3600)
  let re = @api.PrivateKey::from_armored(key.to_armored())
  let now = @primitives.unix_now()
  assert_true(re.is_expired(now + 3601))
  // The key still works while valid: sign and verify at `now`.
  assert_true(re.can_verify(now))
}

///|
test "set_subkey_expiry: encryption capability follows the subkey" {
  let key = @api.generate_ed25519_key("K <k@example.com>")
  let sub_id = key.to_public().subkeys[0].key.key_id()
  let now = @primitives.unix_now()
  let extended = key.set_subkey_expiry(sub_id.exact_view(), 3600)
  assert_true(extended.can_encrypt(now))
  assert_false(extended.can_encrypt(now + 3601))
  // Signing is untouched by a subkey expiry.
  let sig = @api.sign_detached(b"x", extended)
  assert_eq(
    @api.verify_detached(b"x", sig, extended.to_public()),
    @api.VerifyStatus::Ok,
  )
  // Round trip: import validates the re-issued binding and keeps the
  // expiry semantics.
  let re = @api.PrivateKey::from_armored(extended.to_armored())
  assert_false(re.can_encrypt(now + 3601))
  assert_true(re.can_encrypt(now))
}

///|
test "set_subkey_expiry: an unknown subkey id is an error" {
  let key = @api.generate_ed25519_key("K <k@example.com>")
  let raised = try {
    let _ = key.set_subkey_expiry(
      Bytes::from_array([1, 2, 3, 4]).exact_view(),
      60,
    )
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("no subkey of this key matches"))
      true
    }
  }
  assert_true(raised)
}

///|
test "KeyGenBuilder::expires stamps both self-signature and binding" {
  let key = @api.pgp()
    .key_generation()
    .add_user_id("G <g@example.com>")
    .expires(3600)
    .generate()
  let now = @primitives.unix_now()
  assert_false(key.is_expired(now))
  assert_true(key.is_expired(now + 3601))
  // The binding carries the same lifetime, so encryption dies with the key.
  assert_true(key.can_encrypt(now))
  assert_false(key.can_encrypt(now + 3601))
}

///|
test "re-signing operations require an unlocked key" {
  let locked = @api.generate_ed25519_key("L <l@example.com>").lock("pw")
  let raised = try {
    let _ = locked.set_expiry(3600)
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
test "set_expiry re-issues every user id certification with the created stamp" {
  // A multi-User-ID key: the expiry must land on BOTH certifications —
  // a bug that re-signed only the first would pass single-UID tests.
  let key = @api.generate_ed25519_key("One <one@example.com>")
    .add_user_id("Two <two@example.com>")
    .set_expiry(3600, created=1700000000)
  let pubk = key.to_public()
  for b in pubk.user_ids {
    assert_eq(b.self_signature.key_expiration_time(), 3600)
    assert_eq(b.self_signature.creation_time(), Some(1700000000))
  }
  // Import validates both re-issued certifications and keeps the semantics.
  let re = @api.PrivateKey::from_armored(key.to_armored())
  let now = @primitives.unix_now()
  assert_true(re.is_expired(now + 3601))
}

///|
test "set_expiry stamps the v6 direct-key signature too" {
  let key = @api.generate_ed25519_v6_key("V <v@example.com>").set_expiry(
    3600,
    created=1700000001,
  )
  let direct = key.direct_signature.unwrap()
  assert_eq(direct.key_expiration_time(), 3600)
  assert_eq(direct.creation_time(), Some(1700000001))
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_eq(re.direct_signature.unwrap().key_expiration_time(), 3600)
}

///|
test "add_signing_subkey: v6 key gets a cross-certified native Ed25519 subkey" {
  let key = @api.generate_ed25519_v6_key("R6S <r6s@example.com>").add_signing_subkey(
    created=1700000003,
  )
  let re = @api.PrivateKey::from_armored(key.to_armored())
  assert_eq(re.subkeys.length(), 2)
  assert_eq(re.subkeys[1].binding.creation_time(), Some(1700000003))
  let pubk = re.to_public()
  let sign_sub = pubk.subkeys[1]
  let body = @packet.find_subpacket(
    sign_sub.binding.unhashed_subpackets,
    @packet.SIGSUB_EMBEDDED_SIGNATURE,
  )
  let embedded = @packet.SignaturePacket::parse(body.unwrap().exact_view())
  assert_true(@api.verify_key_signature(embedded, sign_sub.key, pubk.primary))
  // Signatures still verify end to end after the rotation.
  let sig = @api.sign_detached(b"v6 signing rotation", re)
  assert_eq(
    @api.verify_detached(b"v6 signing rotation", sig, pubk),
    @api.VerifyStatus::Ok,
  )
}

///|
test "set_subkey_expiry honors the created stamp" {
  let key = @api.generate_ed25519_key("K <k@example.com>")
  let sub_id = key.to_public().subkeys[0].key.key_id()
  let extended = key.set_subkey_expiry(
    sub_id.exact_view(),
    3600,
    created=1700000002,
  )
  assert_eq(extended.subkeys[0].binding.creation_time(), Some(1700000002))
  assert_eq(extended.subkeys[0].binding.key_expiration_time(), 3600)
}

///|
test "extension operations refuse locked keys" {
  let locked = @api.generate_ed25519_key("L <l@example.com>").lock("pw")
  let raised = try {
    let _ = locked.add_encryption_subkey()
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("unlock"))
      true
    }
  }
  assert_true(raised)
  let raised2 = try {
    let _ = locked.add_signing_subkey()
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("unlock"))
      true
    }
  }
  assert_true(raised2)
  let raised3 = try {
    let _ = locked.add_user_id("N <n@example.com>")
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("unlock"))
      true
    }
  }
  assert_true(raised3)
}

///|
test "set_expiry rejects lifetimes beyond the 4-octet subpacket" {
  let raised = try {
    let _ = @api.generate_ed25519_key("O <o@example.com>").set_expiry(
      4294967296L,
    )
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("4-octet subpacket"))
      true
    }
  }
  assert_true(raised)
}
