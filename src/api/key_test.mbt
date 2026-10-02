///|
test "generate key with verifiable self-signatures" {
  let key = @api.generate_key("Tester <tester@example.com>", bits=1024)
  // Primary self-certification verifies.
  let ok = @api.verify_key_signature(
    key.self_signature,
    key.primary.public,
    key.primary.public,
    user_id=key.user_id,
  )
  assert_true(ok)
  // Subkey binding verifies.
  let ok2 = @api.verify_key_signature(
    key.subkey_binding.unwrap(),
    key.primary.public,
    key.encryption_subkey.unwrap().public,
  )
  assert_true(ok2)
  // Subkey differs from primary.
  assert_true(
    key.primary.public.key_id() !=
    key.encryption_subkey.unwrap().public.key_id(),
  )
}

///|
test "key export/import roundtrip via armor" {
  let key = @api.generate_key("Round Trip <rt@example.com>", bits=1024)
  let pub_armored = key.to_public().to_armored()
  let reimported = @api.PublicKey::from_armored(pub_armored)
  assert_eq(reimported.fingerprint(), key.to_public().fingerprint())
  assert_eq(reimported.user_id(), "Round Trip <rt@example.com>")
  // Public armor must NOT contain secret packets.
  let block = @armor.decode(pub_armored)
  let packets = @packet.parse_packets(block.data().view())
  for p in packets {
    assert_false(
      p.tag() == @packet.SecretKey || p.tag() == @packet.SecretSubkey,
    )
  }
  // Private armor roundtrip.
  let priv_armored = key.to_armored()
  let re_priv = @api.PrivateKey::from_armored(priv_armored)
  assert_eq(re_priv.fingerprint(), key.fingerprint())
  assert_false(re_priv.is_locked())
}

///|
test "lock and unlock with passphrase" {
  let key = @api.generate_key("Locked <lk@example.com>", bits=1024)
  let locked = key.lock("secret pass")
  assert_true(locked.is_locked())
  // Wrong passphrase fails.
  let bad = try? locked.unlock("wrong")
  assert_true(bad.is_err())
  // Correct passphrase recovers equivalent secret material.
  let unlocked = locked.unlock("secret pass")
  assert_false(unlocked.is_locked())
  assert_eq(unlocked.primary.secret_material, key.primary.secret_material)
  // The locked key round-trips through armor.
  let armored = locked.to_armored()
  let re = @api.PrivateKey::from_armored(armored)
  assert_true(re.is_locked())
  let back = re.unlock("secret pass")
  assert_eq(back.primary.secret_material, key.primary.secret_material)
}

///|
test "public key encrypt / private key decrypt" {
  let key = @api.generate_key("Alice <alice@example.com>", bits=1024)
  let plaintext = @primitives.utf8_bytes("hello Alice, this is RSA + SEIPD")
  let armored = @api.encrypt_to_recipients(
    plaintext,
    [key.to_public()],
    file_name="msg.txt",
  )
  let decrypted = @api.decrypt_with_private_key(armored, key)
  assert_eq(decrypted, plaintext)
}

///|
test "decrypt fails with wrong key" {
  let alice = @api.generate_key("Alice <alice@example.com>", bits=1024)
  let bob = @api.generate_key("Bob <bob@example.com>", bits=1024)
  let plaintext = @primitives.utf8_bytes("for alice only")
  let armored = @api.encrypt_to_recipients(plaintext, [bob.to_public()])
  let result = try? @api.decrypt_with_private_key(armored, alice)
  assert_true(result.is_err())
}

///|
test "two recipients can both decrypt" {
  let alice = @api.generate_key("Alice <alice@example.com>", bits=1024)
  let bob = @api.generate_key("Bob <bob@example.com>", bits=1024)
  let plaintext = @primitives.utf8_bytes("shared message")
  let armored = @api.encrypt_to_recipients(plaintext, [
    alice.to_public(),
    bob.to_public(),
  ])
  assert_eq(@api.decrypt_with_private_key(armored, alice), plaintext)
  assert_eq(@api.decrypt_with_private_key(armored, bob), plaintext)
}
