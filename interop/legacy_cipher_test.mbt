///|
/// M2 legacy-cipher interop: GnuPG 2.4.5 payloads wrapped in the
/// deprecated symmetric algorithms (generated with
/// `gpg --allow-old-cipher-algos --symmetric --cipher-algo CAST5|3DES`)
/// and a secret key passphrase-protected with CAST5 S2K
/// (`gpg --change-passphrase --s2k-cipher-algo CAST5`).

///|
test "decrypt a GnuPG CAST5 symmetric message" {
  let msg = read_testdata("interop_gpg_cast5_message.asc")
  let data = @api.decrypt_with_password(msg, "legacy cast5 pass")
  assert_eq(
    data,
    @primitives.utf8_bytes(
      "CAST5 legacy payload line one\nsecond line 测试中文\n",
    ),
  )
}

///|
test "decrypt a GnuPG 3DES symmetric message" {
  let msg = read_testdata("interop_gpg_3des_message.asc")
  let data = @api.decrypt_with_password(msg, "legacy 3des pass")
  assert_eq(
    data,
    @primitives.utf8_bytes(
      "CAST5 legacy payload line one\nsecond line 测试中文\n",
    ),
  )
}
