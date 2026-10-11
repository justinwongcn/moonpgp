///|
/// M2 legacy-cipher unlock routing: a secret key protected with CAST5 as
/// the usage-254 protection cipher (the shape GnuPG writes for keys whose
/// passphrase was set with `--s2k-cipher-algo CAST5`). gpg-agent refuses
/// to export passphrase-protected keys in loopback mode, so the wire
/// shape is reproduced here from the same primitives the AES path uses;
/// the CAST5 block cipher itself is validated against OpenSSL in
/// `primitives/cast5_test.mbt`.

///|
/// Hand-craft the usage-254 protection shape with CAST5 as the protection
/// cipher (what GnuPG wrote for keys whose passphrase was set with
/// `--s2k-cipher-algo CAST5`): iterated+salted S2K over SHA-1 deriving a
/// 16-octet CAST5 key, no-resync CFB over (secret material || SHA-1
/// check). gpg-agent refuses to export passphrase-protected keys in
/// loopback mode, so the wire shape is reproduced here from the same
/// primitives the AES path uses; the CAST5 block cipher itself is
/// validated against OpenSSL in `primitives/cast5_test.mbt`.
fn cast5_protected(key : PrivateKey, passphrase : String) -> PrivateKey raise {
  let primary = key.primary
  guard primary.s2k_usage == 0 else { @error.fail("key already locked") }
  let salt = @primitives.random_bytes(@s2k.SALT_SIZE)
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha1,
    salt,
    @s2k.encode_count(1024 * 65536),
  )
  let kek = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    @primitives.Cast5.key_size(),
  )
  let bc = @primitives.new_block_cipher(@primitives.Cast5, kek.exact_view())
  let iv = @primitives.random_bytes(8)
  let check = @primitives.Sha1.digest(primary.secret_material.exact_view())
  let plain = primary.secret_material.add(check)
  let locked : @packet.SecretKeyPacket = {
    public: primary.public,
    s2k_usage: 254,
    cipher_algo: @primitives.Cast5.number(),
    aead_algo: 0,
    s2k_spec: {
      let w = @packet.Writer::new()
      w.bytes(s2k.encode().exact_view())
      w.to_bytes()
    },
    iv,
    secret_material: @cipher.cfb_encrypt(
      bc,
      iv.exact_view(),
      plain.exact_view(),
    ),
    dummy: false,
  }
  { ..key, primary: locked, }
}

///|
test "unlock a secret key protected with CAST5 S2K" {
  let fresh = generate_key("CAST5 Holder <c@example.com>", bits=1024)
  let key = cast5_protected(fresh, "cast5keypass")
  assert_true(key.is_locked())
  let unlocked = key.unlock("cast5keypass")
  assert_false(unlocked.is_locked())
  // Unlocking recovers equivalent secret material: the public half
  // re-verifies its own certification, and the RSA secret exponent is
  // back (a sign round-trip would also prove it).
  assert_true(
    verify_key_signature(
      unlocked.self_signature(),
      unlocked.primary.public,
      unlocked.primary.public,
      user_id=unlocked.user_id(),
    ),
  )
  assert_eq(unlocked.primary.secret_material, fresh.primary.secret_material)
}

///|
test "wrong passphrase on a CAST5-protected key fails" {
  let fresh = generate_key("CAST5 Holder <c@example.com>", bits=1024)
  let key = cast5_protected(fresh, "cast5keypass")
  let raised = try {
    let _ = key.unlock("nope")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
