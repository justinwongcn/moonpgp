///|
/// Differential tests against go-crypto (the engine behind gopenpgp v3).
/// The fixtures were produced by go-crypto's own writer with
/// Argon2id + AES-128/OCB (S2K usage octet 253) and the deliberately cheap
/// parameters t=1, p=1, m=2^5 KiB, so these run in the default suite.
///
/// Regenerate with the runnable generator in `testdata/gocrypto/`; it pins
/// go-crypto v1.5.2, and v1.4.1 (the release gopenpgp v3 pins) was verified
/// to produce a structurally identical set — see
/// `testdata/gen_gocrypto_argon2_vectors.md`.

///|
test "unlock a go-crypto Argon2 + OCB v4 secret key" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_gocrypto_v4_argon2_key.asc"),
  )
  assert_true(key.is_locked())
  assert_true(key.is_aead_protected())
  let unlocked = key.unlock("go-crypto-argon2")
  assert_false(unlocked.is_locked())
  assert_eq(unlocked.fingerprint(), key.fingerprint())
}

///|
test "unlock a go-crypto Argon2 + OCB v6 secret key" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_gocrypto_v6_argon2_key.asc"),
  )
  assert_true(key.is_locked())
  assert_true(key.is_aead_protected())
  assert_eq(key.primary.public.version(), 6)
  let unlocked = key.unlock("go-crypto-argon2")
  assert_false(unlocked.is_locked())
  assert_eq(unlocked.fingerprint(), key.fingerprint())
}

///|
test "decrypt a go-crypto Argon2 S2K symmetric message" {
  let message = read_testdata("interop_gocrypto_argon2_msg.asc")
  assert_eq(
    @api.decrypt_with_password(message, "go-crypto-argon2"),
    @primitives.utf8_bytes("written by go-crypto with Argon2 S2K\n"),
  )
}

///|
/// RFC 9580 v6 message interop with go-crypto: a v6 Ed25519 + X25519 key
/// and a v6 PKESK + v2 SEIPD message written by go-crypto.
test "decrypt a go-crypto v6 PKESK + v2 SEIPD message" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_gocrypto_v6_aead_key.asc"),
  )
  assert_eq(key.primary.public.version(), 6)
  assert_eq(key.primary.public.algo(), @packet.Ed25519)
  let subkey = key.subkeys[0].secret
  assert_eq(subkey.public.algo(), @packet.X25519)
  assert_eq(
    @api.decrypt_with_private_key(
      read_testdata("interop_gocrypto_v6_aead_msg.asc"),
      key,
    ),
    @primitives.utf8_bytes("written by go-crypto v6 PKESK + SEIPD v2\n"),
  )
}

///|
test "decrypt a go-crypto v6 SKESK + v2 SEIPD message" {
  assert_eq(
    @api.decrypt_with_password(
      read_testdata("interop_gocrypto_v6_aead_skesk_msg.asc"),
      "go-crypto-v6",
    ),
    @primitives.utf8_bytes("written by go-crypto v6 SKESK\n"),
  )
}
