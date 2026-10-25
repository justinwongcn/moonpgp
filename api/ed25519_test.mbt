///|
test "ed25519 key generation with verifiable self-signature" {
  let key = @api.generate_ed25519_key("Ed <ed@example.com>")
  assert_eq(
    @packet.PublicKeyPacket::algo(key.primary.public),
    @packet.EdDsaLegacy,
  )
  let ok = @api.verify_key_signature(
    key.self_signature(),
    key.primary.public,
    key.primary.public,
    user_id=key.user_id(),
  )
  assert_true(ok)
  // RSA encryption subkey binding verifies against the Ed25519 primary.
  let ok2 = @api.verify_key_signature(
    key.subkeys[0].binding,
    key.primary.public,
    key.subkeys[0].secret.public,
  )
  assert_true(ok2)
  // Fingerprint is a v4 SHA-1 fingerprint.
  assert_eq(key.fingerprint().length(), 20)
}

///|
test "ed25519 key armor roundtrip" {
  let key = @api.generate_ed25519_key("Ed <ed@example.com>")
  let pub_armored = key.to_public().to_armored()
  let re = @api.PublicKey::from_armored(pub_armored)
  assert_eq(re.fingerprint(), key.fingerprint())
  assert_eq(@packet.PublicKeyPacket::algo(re.primary), @packet.EdDsaLegacy)
  // Signature still verifies after the roundtrip.
  let ok = @api.verify_key_signature(
    re.self_signature(),
    re.primary,
    re.primary,
    user_id=re.user_id(),
  )
  assert_true(ok)
}

///|
test "ed25519 detached signature roundtrip" {
  let key = @api.generate_ed25519_key("Ed <ed@example.com>")
  let data = @primitives.utf8_bytes("ed25519 signed data\n")
  let sig = @api.sign_detached(data, key)
  assert_eq(@api.verify_detached(data, sig, key.to_public()), @api.Ok)
  let tampered = @primitives.utf8_bytes("ed25519 signed data X")
  assert_eq(@api.verify_detached(tampered, sig, key.to_public()), @api.Failed)
}

///|
test "ed25519 inline and cleartext signing" {
  let key = @api.generate_ed25519_key("Ed <ed@example.com>")
  let data = @primitives.utf8_bytes("inline ed25519")
  let armored = @api.sign_inline(data, key)
  let (extracted, status) = @api.verify_inline(armored, key.to_public())
  assert_eq(extracted, data)
  assert_eq(status, @api.Ok)
  let ct = @api.sign_cleartext("cleartext from ed25519\n", key)
  let (recovered, status2) = @api.verify_cleartext(ct, key.to_public())
  assert_eq(status2, @api.Ok)
  assert_eq(recovered, "cleartext from ed25519")
}

///|
test "ed25519 primary with ecdh subkey encrypt/decrypt" {
  let key = @api.generate_ed25519_key("Ed <ed@example.com>")
  assert_eq(
    @packet.PublicKeyPacket::algo(key.subkeys[0].secret.public),
    @packet.Ecdh,
  )
  let plaintext = @primitives.utf8_bytes("ecdh subkey under ed25519 primary")
  let armored = @api.encrypt_to_recipients(plaintext, [key.to_public()])
  assert_eq(@api.decrypt_with_private_key(armored, key), plaintext)
}

///|
test "ed25519 sign and encrypt combined" {
  let signer = @api.generate_ed25519_key("S <s@example.com>")
  let recipient = @api.generate_key("R <r@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("ed25519 signed + rsa encrypted")
  let armored = @api.sign_and_encrypt(data, signer, [recipient.to_public()])
  let (extracted, status) = @api.decrypt_and_verify(
    armored,
    [recipient],
    Some(signer.to_public()),
  )
  assert_eq(extracted, data)
  assert_eq(status, @api.Ok)
}
