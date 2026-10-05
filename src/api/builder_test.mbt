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
