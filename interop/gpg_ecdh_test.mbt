///|
/// GnuPG 2.4.5 ECDH (Curve25519Legacy) cross-validation.
///
/// Live-run provenance (both directions verified on 2026-09-29):
///
///   1. We generated the transferable key in interop_our_ecdh_key.asc
///      (Ed25519 primary + cv25519 ECDH subkey, user id
///      "MoonBit ECDH <ecdh@test.local>", primary fingerprint
///      E8A254F4A5D179A6CF47AA0914838E695BCDCA75). GnuPG imported it and
///      shows it as `pub ed25519 [SC] / sub cv25519 [E]`, then encrypted
///      "secret for moonbit ecdh\n" to it (--trust-model always,
///      SEIPD v1) producing interop_gpg_ecdh_message.asc.
///
///   2. We encrypted "moonbit to gpg via ecdh\n" to gpg's own cv25519
///      subkey (7FD33E20FC61FB41 of key C89DF2E7343FF96822EFCBB5FC2473
///      DDB6791DD1); gpg --decrypt reported
///      "encrypted with cv25519 key, ID 7FD33E20FC61FB41" and recovered
///      the plaintext (interop_our_ecdh_message.asc).
fn our_ecdh_fingerprint() -> Bytes raise {
  @primitives.from_hex("e8a254f4a5d179a6cf47aa0914838e695bcdca75")
}

///|
test "decrypt gpg-encrypted ECDH message with our cv25519 subkey" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_our_ecdh_key.asc"),
  )
  assert_false(key.is_locked())
  assert_eq(key.fingerprint(), our_ecdh_fingerprint())
  assert_eq(
    @packet.PublicKeyPacket::algo(key.subkeys[0].secret.public),
    @packet.Ecdh,
  )
  let plaintext = @api.decrypt_with_private_key(
    read_testdata("interop_gpg_ecdh_message.asc"),
    key,
  )
  assert_eq(plaintext, @primitives.utf8_bytes("secret for moonbit ecdh\n"))
}

///|
test "our ECDH encrypt/decrypt roundtrip against gpg vectors" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_our_ecdh_key.asc"),
  )
  // Fresh message both ways through our own implementation.
  let msg = @primitives.utf8_bytes("roundtrip through our ecdh subkey")
  let armored = @api.encrypt_to_recipients(msg, [key.to_public()])
  assert_eq(@api.decrypt_with_private_key(armored, key), msg)
  // The message we produced for gpg (live-verified) must parse with an
  // ECDH PKESK aimed at gpg's subkey.
  let block = @armor.decode(read_testdata("interop_our_ecdh_message.asc"))
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(block).exact_view(),
  )
  let mut saw_ecdh_pkesk = false
  for p in packets {
    if p.tag() == @packet.Pkesk {
      let pkesk = @packet.PkeskPacket::parse(p.body().exact_view())
      assert_eq(pkesk.pub_algo(), @packet.Ecdh)
      assert_eq(pkesk.ecdh_ephemeral().length(), 33)
      assert_eq(pkesk.ecdh_ephemeral()[0], b'\x40')
      saw_ecdh_pkesk = true
    }
  }
  assert_true(saw_ecdh_pkesk)
}

///|
/// GnuPG 2.4.5 BZip2 cross-validation (live-verified 2026-10-28): the
/// interop_our_ecdh_key key was imported into gpg and used as recipient
/// for `gpg --compress-algo bzip2 --bzip2-compress-level 9 --encrypt`;
/// `gpg --list-packets` shows `:compressed packet: algo=3`. This is the
/// shape a gpg sender produces whenever its config names bzip2 — before
/// the BZip2 codec existed the library could not open such mail at all.
test "decrypt a GnuPG message compressed with BZip2" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_our_ecdh_key.asc"),
  )
  let plain = @api.decrypt_with_private_key(
    read_testdata("interop_gpg_bzip2_message.asc"),
    key,
  )
  assert_eq(
    plain,
    @primitives.utf8_bytes("bzip2 interop payload\nsecond line\n"),
  )
}
