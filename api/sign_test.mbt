///|
test "stress: repeated keygen with verification" {
  for i in 0..<6 {
    try {
      let key = @api.generate_key("Stress <s\{i}@example.com>", bits=1024)
      let ok1 = @api.verify_key_signature(
        key.self_signature(),
        key.primary.public,
        key.primary.public,
        user_id=key.user_id(),
      )
      let ok2 = @api.verify_key_signature(
        key.subkey_binding.unwrap(),
        key.primary.public,
        key.encryption_subkey.unwrap().public,
      )
      assert_true(ok1)
      assert_true(ok2)
    } catch {
      e => {
        println("STRESS-ERR at \{i}: \{e}")
        abort("stress failed")
      }
    }
  }
}

///|
test "detached signature roundtrip" {
  let key = @api.generate_key("Signer <s@example.com>", bits=1024)
  let data = @primitives.utf8_bytes("document body\nsecond line\n")
  let sig = @api.sign_detached(data, key)
  assert_eq(@api.verify_detached(data, sig, key.to_public()), @api.Ok)
  // Tampered data must fail verification.
  let tampered = @primitives.utf8_bytes("document body\nsecond line X")
  assert_eq(@api.verify_detached(tampered, sig, key.to_public()), @api.Failed)
}

///|
test "text mode signature canonicalizes newlines" {
  let key = @api.generate_key("Signer <s@example.com>", bits=1024)
  // Data with bare LFs; verifier presents CRLF form — same canonical hash.
  let data = @primitives.utf8_bytes("line one\nline two\n")
  let sig = @api.sign_detached(data, key, text_mode=true)
  let crlf = @primitives.utf8_bytes("line one\r\nline two\r\n")
  assert_eq(@api.verify_detached(crlf, sig, key.to_public()), @api.Ok)
  // Binary mode must NOT accept the CRLF variant.
  let sig_bin = @api.sign_detached(data, key)
  assert_eq(@api.verify_detached(crlf, sig_bin, key.to_public()), @api.Failed)
}

///|
test "inline signature roundtrip" {
  let key = @api.generate_key("Signer <s@example.com>", bits=1024)
  let data = @primitives.utf8_bytes("signed payload")
  let armored = @api.sign_inline(data, key)
  let (extracted, status) = @api.verify_inline(armored, key.to_public())
  assert_eq(extracted, data)
  assert_eq(status, @api.Ok)
}

///|
test "sign and encrypt, then decrypt and verify" {
  let signer = @api.generate_key("Sender <from@example.com>", bits=1024)
  let recipient = @api.generate_key("Recipient <to@example.com>", bits=1024)
  let data = @primitives.utf8_bytes("confidential and authenticated")
  let armored = @api.sign_and_encrypt(data, signer, [recipient.to_public()])
  let (extracted, status) = @api.decrypt_and_verify(
    armored,
    [recipient],
    Some(signer.to_public()),
  )
  assert_eq(extracted, data)
  assert_eq(status, @api.Ok)
}

///|
test "keyring lookup by key id" {
  let alice = @api.generate_key("Alice <a@example.com>", bits=1024)
  let ring = @api.KeyRing::new()
  ring.add_public(alice.to_public())
  assert_eq(ring.public_count(), 1)
  let pub_key = alice.to_public()
  let found = ring.find_verification_key(pub_key.key_id())
  assert_true(found is Some(_))
  // M1: lookups are capability-aware. The encryption-only subkey (key
  // flags 0x0C) no longer resolves as a verification key, but it does
  // resolve as an encryption key.
  let sub_id = alice.to_public().encryption_subkey.unwrap().key_id()
  assert_true(ring.find_verification_key(sub_id) is None)
  assert_true(ring.find_encryption_key(sub_id) is Some(_))
}

///|
test "builder: password encryption and decryption" {
  let data = @primitives.utf8_bytes("builder payload")
  let encrypt = @api.pgp().encryption().password("pw1").finish()
  let armored = encrypt(data)
  let decrypt = @api.pgp().decryption().password("pw1").finish()
  match decrypt(armored) {
    @api.Data(d) => assert_eq(d, data)
    _ => abort("unexpected decrypt result")
  }
}

///|
test "builder: public key path with signature verification" {
  let signer = @api.generate_key("S <s@example.com>", bits=1024)
  let recipient = @api.generate_key("R <r@example.com>", bits=1024)
  let data = @primitives.utf8_bytes("builder pk payload")
  let encrypt = @api.pgp()
    .encryption()
    .recipient(recipient.to_public())
    .sign_with(signer)
    .finish()
  let armored = encrypt(data)
  let decrypt = @api.pgp()
    .decryption()
    .decryption_key(recipient)
    .verification_key(signer.to_public())
    .finish()
  match decrypt(armored) {
    @api.Verified(d) => assert_eq(d, data)
    _ => abort("unexpected decrypt result")
  }
}

///|
test "builder: key generation" {
  let key = @api.pgp()
    .key_generation()
    .add_user_id("B <b@example.com>")
    .rsa_bits(1024)
    .generate()
  assert_eq(key.user_id(), "B <b@example.com>")
  assert_eq(key.fingerprint().length(), 20)
}

///|
test "detached signature with a fixed creation time is reproducible" {
  // RSA PKCS#1 v1.5 and Ed25519 are deterministic, so the same key, data and
  // time give the same signature (needed for reproducible builds).
  let data = @primitives.utf8_bytes("document body\n")
  for
    key in [
      @api.generate_key("Signer <s@example.com>", bits=1024),
      @api.generate_ed25519_key("Signer <s@example.com>"),
    ] {
    let a = @api.sign_detached(data, key, created=1700000000)
    let b = @api.sign_detached(data, key, created=1700000000)
    assert_eq(a, b)
    assert_eq(@api.verify_detached(data, a, key.to_public()), @api.Ok)
    let later = @api.sign_detached(data, key, created=1700000001)
    assert_true(a != later)
  }
}
