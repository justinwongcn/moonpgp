///|
/// Read a file from the project's testdata directory.
fn read_testdata(name : String) -> String raise {
  @fs.read_file_to_string("testdata/\{name}") catch {
    _ =>
      raise @error.PgpError::PgpError(msg="interop: cannot read testdata file")
  }
}

///|
/// ProtonMail gopenpgp `testdata/keyring_privateKey`: an OpenPGP.js v0.7.1
/// RSA transferable secret key locked with the passphrase "apple"
/// (documented in gopenpgp's keyring_test.go). Parsing, fingerprinting and
/// unlocking must all work against this third-party artifact.
test "unlock gopenpgp keyring_privateKey (RSA, passphrase 'apple')" {
  let armored = read_testdata("keyring_privateKey")
  let block = @armor.decode(armored)
  assert_eq(@armor.ArmorBlock::armor_type(block), @armor.PrivateKey)
  let key = @api.PrivateKey::from_armored(armored)
  assert_true(key.is_locked())
  let unlocked = key.unlock("apple")
  assert_false(unlocked.is_locked())
  // The public half matches keyring_publicKey (same source key).
  let pub_armored = read_testdata("keyring_publicKey")
  let pub_key = @api.PublicKey::from_armored(pub_armored)
  assert_eq(pub_key.fingerprint(), unlocked.fingerprint())
}

///|
/// Wrong passphrase must be rejected with a clear error.
test "wrong passphrase on gopenpgp key fails" {
  let key = @api.PrivateKey::from_armored(read_testdata("keyring_privateKey"))
  let raised = try {
    let _ = key.unlock("wrong passphrase")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
/// gopenpgp `testdata/message_signed` is a signed+encrypted message whose
/// session key is RSA-wrapped to keyring_privateKey, and whose plaintext
/// is `testdata/message_plaintext` (see gopenpgp's
/// TestDataPacketDecryption).
test "decrypt gopenpgp message_signed to message_plaintext" {
  let key = @api.PrivateKey::from_armored(read_testdata("keyring_privateKey")).unlock(
    "apple",
  )
  let message = read_testdata("message_signed")
  let data = @api.decrypt_with_private_key(message, key)
  // gopenpgp encrypts the file content with its trailing newline trimmed
  // (readTestFile(name, trimNewline=true) in their tests).
  let expected = read_testdata("message_plaintext")
  let mut end = expected.length()
  while end > 0 && (expected[end - 1] == '\n' || expected[end - 1] == '\r') {
    end = end - 1
  }
  assert_eq(data, @primitives.utf8_bytes(expected[0:end].to_owned()))
}

///|
/// The same key must be able to verify the OpenPGP.js self-certifications
/// shipped in the keyring (cryptographic cross-validation of our v4
/// signature hashing against another implementation).
test "verify self-certification of gopenpgp key" {
  let key = @api.PrivateKey::from_armored(read_testdata("keyring_privateKey"))
  let ok = @api.verify_key_signature(
    key.self_signature,
    key.primary.public,
    key.primary.public,
    user_id=key.user_id,
  )
  assert_true(ok)
}

///|
/// gopenpgp `testdata/key_dummy` is a GnuPG transferable key whose secret
/// material was moved to a smartcard: the SecretKey packet carries the
/// GnuPG "GNU dummy" S2K marker. It must parse, report locked, and refuse
/// to unlock (gopenpgp also only parses this key in its tests).
test "parse gopenpgp key_dummy (GnuPG smartcard dummy)" {
  let key = @api.PrivateKey::from_armored(read_testdata("key_dummy"))
  assert_true(key.is_locked())
  let raised = try {
    let _ = key.unlock("")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
