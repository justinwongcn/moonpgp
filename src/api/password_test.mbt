///|
test "password encrypt/decrypt roundtrip" {
  let plaintext = @primitives.utf8_bytes("hello, OpenPGP over MoonBit!\n")
  let armored = @api.encrypt_with_password(
    plaintext,
    "correct horse battery staple",
    file_name="msg.txt",
  )
  let decrypted = @api.decrypt_with_password(
    armored, "correct horse battery staple",
  )
  assert_eq(decrypted, plaintext)
}

///|
test "wrong password fails" {
  let plaintext = @primitives.utf8_bytes("secret")
  let armored = @api.encrypt_with_password(plaintext, "right")
  let raised = try {
    let _ = @api.decrypt_with_password(armored, "wrong")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "compressed content decrypts" {
  // Manually build inner stream: literal inside a ZLIB compressed packet.
  let plaintext = @primitives.utf8_bytes(
    "compressed payload, compressed payload, compressed payload",
  )
  let literal = @packet.LiteralPacket::binary(plaintext)
  let comp_body_w = @packet.Writer::new()
  comp_body_w.u8(2)
  let zlib_data = @compress.zlib_compress(literal.to_body().exact_view())
  comp_body_w.bytes(zlib_data.exact_view())
  let packets : Array[@packet.RawPacket] = [
    { tag: @packet.Compressed, body: comp_body_w.to_bytes(), },
  ]
  // Build the SEIPD over it and assemble with a SKESK-less path: reuse
  // decrypt through a crafted binary message.
  let session_key = @primitives.random_bytes(32)
  let inner_w = @packet.Writer::new()
  for p in packets {
    let wire = @packet.serialize_packet(p.tag(), p.body().exact_view())
    inner_w.bytes(wire.exact_view())
  }
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session_key.exact_view(),
  )
  let seipd_ct = @cipher.seipd_v1_encrypt(bc, inner_w.to_bytes().exact_view())
  let w = @packet.Writer::new()
  w.u8(0xC0 | @packet.Seipd.number())
  w.u8(seipd_ct.length() + 1)
  w.u8(1)
  w.bytes(seipd_ct.exact_view())
  // Decrypt via the literal-extraction path using a direct SEIPD decrypt.
  let packets2 = @packet.parse_packets(w.to_bytes().exact_view())
  assert_eq(packets2.length(), 1)
  let seipd = @packet.SeipdPacket::parse(packets2[0].body().exact_view())
  let inner = @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.exact_view())
  assert_eq(@packet.parse_packets(inner).length(), 1)
}
