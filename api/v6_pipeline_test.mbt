///|
/// The sign/encrypt/decrypt pipeline must handle the same packet shapes as
/// `encrypt_to_recipients`/`decrypt_with_private_key`. It used to hardcode
/// AES-256 + SEIPD v1 while `create_pkesk` emitted a v6 PKESK for an X25519
/// recipient — a combination RFC 9580 §10.3.2.1 forbids ("The payload
/// following any v6 PKESK or v6 SKESK packet MUST be a v2 SEIPD") and which
/// the library could not even read back ("unsupported session cipher 0").

///|
test "sign_and_encrypt pairs a v6 PKESK with a v2 SEIPD and round-trips" {
  let key = @api.generate_ed25519_v6_key("V6 Pipeline <v6pipe@test.local>")
  let public = key.to_public()
  let data = @primitives.utf8_bytes("v6 signed and encrypted\n")
  let armored = @api.sign_and_encrypt(data, key, [public])
  let block = @armor.decode(armored)
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut pkesk_version = 0
  let mut seipd_version = 0
  for p in packets {
    if p.tag() == @packet.Pkesk {
      pkesk_version = @packet.PkeskPacket::parse(p.body().exact_view()).version()
    }
    if p.tag() == @packet.Seipd {
      seipd_version = @packet.SeipdPacket::parse(p.body().exact_view()).version
    }
  }
  assert_eq(pkesk_version, 6)
  assert_eq(seipd_version, 2)
  assert_eq(@api.decrypt_with_private_key(armored, key), data)
}

///|
test "decrypt_and_verify consumes a v6 message the library produced" {
  let key = @api.generate_ed25519_v6_key("V6 Pipeline <v6pipe@test.local>")
  let public = key.to_public()
  let data = @primitives.utf8_bytes("v6 decrypt_and_verify\n")
  let armored = @api.sign_and_encrypt(data, key, [public])
  let (got, status) = @api.decrypt_and_verify(armored, [key], Some(public))
  assert_eq(got, data)
  assert_eq(status, @api.Ok)
}
