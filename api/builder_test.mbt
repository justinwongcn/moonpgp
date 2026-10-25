///|
test "encryption builder branches do not share mutable state" {
  // F05: builder methods used to push into a shared Array, so a later
  // branch leaked into earlier ones — with_one below would have encrypted
  // with "two" before the fix.
  let base = @api.pgp().encryption()
  let with_two = base.password("two")
  let with_one = base.password("one")
  let armored = with_one.finish()(@primitives.utf8_bytes("aliasing probe"))
  // with_one encrypted with "one": decrypting with "one" succeeds...
  let opened = @api.pgp().decryption().password("one").finish()(armored)
  let ok = match opened {
    @api.Data(_) => true
    _ => false
  }
  assert_true(ok)
  // ...and "two" must not open it.
  let wrong = try {
    let _ = @api.pgp().decryption().password("two").finish()(armored)
    false
  } catch {
    _ => true
  }
  assert_true(wrong)
  // Symmetrically, with_two still encrypts with "two" and only "two".
  let armored_two = with_two.finish()(
    @primitives.utf8_bytes("aliasing probe two"),
  )
  let opened_two = @api.pgp().decryption().password("two").finish()(armored_two)
  let ok_two = match opened_two {
    @api.Data(_) => true
    _ => false
  }
  assert_true(ok_two)
  let wrong_one = try {
    let _ = @api.pgp().decryption().password("one").finish()(armored_two)
    false
  } catch {
    _ => true
  }
  assert_true(wrong_one)
}

///|
/// Task 3: the encryption builder's v6 password path (v6 SKESK + v2 SEIPD,
/// cheap iterated S2K for test speed — the Argon2 form is exercised by the
/// argon2/interop suites).
test "builder: v6 password encryption and decryption" {
  let data = @primitives.utf8_bytes("v6 builder payload")
  let encrypt = @api.pgp()
    .encryption()
    .password_v6("alpha", argon2=false)
    .password_v6("beta", argon2=false)
    .finish()
  let armored = encrypt(data)
  // Both passphrases open the message (one SKESK each, shared session key).
  assert_eq(@api.decrypt_with_password(armored, "alpha"), data)
  assert_eq(@api.decrypt_with_password(armored, "beta"), data)
  // The builder's password-decrypt path handles v6 too.
  let decrypt = @api.pgp().decryption().password("beta").finish()
  match decrypt(armored) {
    Data(d) => assert_eq(d, data)
    _ => fail("expected Data")
  }
}

///|
test "builder: mixing v4 and v6 password shapes is rejected" {
  let encrypt = @api.pgp()
    .encryption()
    .password("v4-shape")
    .password_v6("v6-shape", argon2=false)
    .finish()
  let raised = try {
    let _ = encrypt(@primitives.utf8_bytes("x"))
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("cannot mix v4 and v6"))
      true
    }
  }
  assert_true(raised)
}
