///|
/// `is_locked` / `is_aead_protected` must describe the whole private key,
/// not just the primary packet: `unlock` handles the primary and the
/// encryption subkey together, and gopenpgp's `IsLocked` counts protected
/// subkeys too. Reporting `false` for "primary plaintext + subkey
/// protected" made callers treat a key whose subkey still needs a
/// passphrase as ready to use.
///
/// White-box because `PrivateKey` is `pub struct` (fields readable,
/// constructor not public), so the mixed protection state is built here by
/// functional update.

///|
test "is_locked / is_aead_protected consider the encryption subkey" {
  let key = generate_ed25519_v6_key("Sub <sub@test.local>")
  assert_false(key.is_locked())
  assert_false(key.is_aead_protected())
  let locked = key.lock_argon2("pw", passes=1, parallelism=1, memory_exp=5)
  assert_true(locked.is_locked())
  assert_true(locked.is_aead_protected())
  // The same key with the primary packet's protection stripped: the only
  // protected component left is the encryption subkey.
  let mixed : PrivateKey = {
    ..locked,
    primary: { ..locked.primary, s2k_usage: 0, },
  }
  assert_true(mixed.is_locked())
  assert_true(mixed.is_aead_protected())
  // Unlocking the mixed key really does clear every component.
  assert_false(mixed.unlock("pw").is_locked())
}
