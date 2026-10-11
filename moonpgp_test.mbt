///|
/// Black-box acceptance tests for the root facade: everything below is
/// written exactly the way a downstream consumer would write it after a
/// bare `import "justinwongcn/moonpgp"`.
test "root facade: password encrypt/decrypt roundtrip" {
  let msg = @moonpgp.encrypt_with_password(b"hello facade", "hunter2")
  let pt = @moonpgp.decrypt_with_password(msg, "hunter2")
  assert_eq(pt, b"hello facade")
  ignore(@moonpgp.DEFAULT_MAX_DECOMPRESSED_BYTES)
}

///|
test "root facade: key generate / armor / reimport / methods" {
  let key = @moonpgp.generate_key("alice@example.com")
  let armored = key.to_armored()
  let re = @moonpgp.PrivateKey::from_armored(armored)
  assert_eq(re.fingerprint(), key.fingerprint())
  assert_eq(re.user_id(), "alice@example.com")
  // Re-exported option type is nameable and rides on the facade.
  let _ : @moonpgp.CipherAlgo = @moonpgp.generate_session_key().algo()
}

///|
test "root facade: builder chain and DecryptResult pattern match" {
  let key = @moonpgp.generate_key("alice@example.com")
  let enc = @moonpgp.pgp().encryption().recipient(key.to_public()).finish()(
    b"payload",
  )
  let open = @moonpgp.pgp().decryption().decryption_key(key).finish()
  match open(enc) {
    Data(data) => assert_eq(data, b"payload")
    Verified(data) => assert_eq(data, b"payload")
    SignatureError(_) => fail("unexpected signature error")
  }
}

///|
test "root facade: sign and verify through re-exported values" {
  let key = @moonpgp.generate_ed25519_v6_key("alice@example.com")
  let signed = @moonpgp.sign_inline(b"signed payload", key)
  let (pt, status) = @moonpgp.verify_inline(signed, key.to_public())
  assert_eq(pt, b"signed payload")
  assert_eq(status, @moonpgp.VerifyStatus::Ok)
}
