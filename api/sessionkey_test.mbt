///|
/// M3 session-key API tests: generate → seal to a held session key →
/// decrypt, recovery from password and public-key messages, and the
/// negative paths.

///|
test "session key round trip (bare SEIPD, out-of-band key)" {
  let sk = @api.generate_session_key()
  assert_eq(sk.key().length(), 32)
  assert_eq(sk.algo(), @primitives.Aes256)
  let data = @primitives.utf8_bytes("out of band session key payload")
  let msg = @api.encrypt_to_session_key(data, sk, file_name="notes.txt")
  let out = @api.decrypt_to_session_key(msg, sk)
  assert_eq(out, data)
  // A differently sized key cannot decrypt it (MDC fails).
  let wrong = @api.generate_session_key()
  let raised = try {
    let _ = @api.decrypt_to_session_key(msg, wrong)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "session key with a non-default cipher" {
  let sk = @api.generate_session_key(algo=@primitives.Cast5)
  assert_eq(sk.key().length(), 16)
  let data = @primitives.utf8_bytes("cast5 session key payload")
  let msg = @api.encrypt_to_session_key(data, sk)
  assert_eq(@api.decrypt_to_session_key(msg, sk), data)
}

///|
test "SessionKey::new validates the key length" {
  let raised = try {
    let _ = @api.SessionKey::new(
      @primitives.from_hex("00112233"),
      @primitives.Aes256,
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "recover the session key of a password-encrypted message" {
  let msg = @api.encrypt_with_password(
    @primitives.utf8_bytes("recover me"),
    "some passphrase",
  )
  let sk = @api.recover_session_key_with_password(msg, "some passphrase")
  assert_eq(sk.algo(), @primitives.Aes256)
  // The recovered key decrypts the very same message.
  assert_eq(
    @api.decrypt_to_session_key(msg, sk),
    @primitives.utf8_bytes("recover me"),
  )
  // A wrong passphrase either fails or yields a useless key; decrypting
  // with a deliberately different session key must fail.
  let junk = @api.generate_session_key()
  let raised = try {
    let _ = @api.decrypt_to_session_key(msg, junk)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "recover the session key of a public-key-encrypted message" {
  let recipient = @api.generate_key("R <r@example.com>", bits=1024)
  let data = @primitives.utf8_bytes("pk recovery payload")
  let msg = @api.encrypt_to_recipients(data, [recipient.to_public()])
  let sk = @api.recover_session_key_with_key(msg, recipient)
  assert_eq(@api.decrypt_to_session_key(msg, sk), data)
  // A different key finds no PKESK addressed to it.
  let other = @api.generate_key("O <o@example.com>", bits=1024)
  let raised = try {
    let _ = @api.recover_session_key_with_key(msg, other)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "decrypt_to_session_key also opens a normal public-key message" {
  let recipient = @api.generate_key("R2 <r2@example.com>", bits=1024)
  let data = @primitives.utf8_bytes("known key payload")
  let msg = @api.encrypt_to_recipients(data, [recipient.to_public()])
  let sk = @api.recover_session_key_with_key(msg, recipient)
  assert_eq(@api.decrypt_to_session_key(msg, sk), data)
}
