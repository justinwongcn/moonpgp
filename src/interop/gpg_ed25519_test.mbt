///|
/// GnuPG 2.4.5 cross-validation with a gpg-native Ed25519 key
/// ("GnuPG Ed <gpg@test.local>", primary fingerprint
/// C89DF2E7343FF96822EFCBB5FC2473DDB6791DD1, cv25519 ECDH subkey
/// 7FD33E20FC61FB41). gpg signed "hello gpg ed25519\n" with its Ed25519
/// primary (detached and cleartext); we parse its transferable public
/// key — including the ECDH subkey we do not implement semantically —
/// and verify both signatures.
fn gpg_ed25519_fingerprint() -> Bytes raise {
  @primitives.from_hex("c89df2e7343ff96822efcbb5fc2473ddb6791dd1")
}

///|
test "parse gpg ed25519 key with ecdh subkey" {
  let key = @api.PublicKey::from_armored(
    read_testdata("interop_gpg_ed25519_pub.asc"),
  )
  assert_eq(key.fingerprint(), gpg_ed25519_fingerprint())
  assert_eq(key.user_id(), "GnuPG Ed <gpg@test.local>")
  assert_eq(@packet.PublicKeyPacket::algo(key.primary), @packet.EdDsaLegacy)
  let sub = key.encryption_subkey.unwrap()
  assert_eq(@packet.PublicKeyPacket::algo(sub), @packet.Ecdh)
  // Subkey round-trips to the exact wire bytes gpg wrote.
  let body = sub.to_body()
  let re = @packet.PublicKeyPacket::parse(body.exact_view())
  assert_eq(@packet.PublicKeyPacket::algo(re), @packet.Ecdh)
  assert_eq(re.params()[2][3].to_int(), 7) // AES-128 key wrap
}

///|
test "verify gpg ed25519 detached signature" {
  let key = @api.PublicKey::from_armored(
    read_testdata("interop_gpg_ed25519_pub.asc"),
  )
  let data = @primitives.utf8_bytes("hello gpg ed25519\n")
  let status = @api.verify_detached(
    data,
    read_testdata("interop_gpg_ed25519_sig.asc"),
    key,
  )
  assert_eq(status, @api.Ok)
  let tampered = @primitives.utf8_bytes("hello gpg ed25519!")
  assert_eq(
    @api.verify_detached(
      tampered,
      read_testdata("interop_gpg_ed25519_sig.asc"),
      key,
    ),
    @api.Failed,
  )
}

///|
test "verify gpg ed25519 cleartext signature" {
  let key = @api.PublicKey::from_armored(
    read_testdata("interop_gpg_ed25519_pub.asc"),
  )
  let (recovered, status) = @api.verify_cleartext(
    read_testdata("interop_gpg_ed25519_cleartext.asc"),
    key,
  )
  assert_eq(status, @api.Ok)
  assert_eq(recovered, "hello gpg ed25519")
}
