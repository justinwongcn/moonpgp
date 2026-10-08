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

///|
/// draft-ietf-openpgp-rfc4880bis A.4 end-to-end: the RFC's complete
/// AEAD message (v5 SKESK holding the OCB-sealed session key, then a
/// tag-20 packet) decrypts with the passphrase "password" to the
/// literal payload "Hello, world!\n".
test "rfc4880bis A.4 aead message decrypts end to end" {
  let msg = @primitives.from_hex(
    "c33d" +
    "0507020308" +
    "9f0b7da3e5ea6477" +
    "90" +
    "99e326e5400a90936cefb4e8eba08c" +
    "6773716d1f2714540a38fcac529949da" +
    "c529d3de31e15b4aeb729e330033dbed" +
    "d449" +
    "0107020e" +
    "5ed2bc1e470abe8f1d644c7a6c8a56" +
    "7b0f7701196611a154ba9c2574cd056284a8ef68035c" +
    "623d93cc708a43211bb6eaf2b27f7c18" +
    "d571bcd83b20add3a08b73af15b9a098",
  )
  let data = @api.decrypt_binary_with_password(msg.exact_view(), "password")
  assert_eq(@utf8.decode_lossy(data.exact_view()), "Hello, world!\n")
}

///|
/// The AEAD writer round-trips through the reader, and the produced
/// message really is a v5 SKESK plus a tag-20 packet.
test "password aead mode round-trip" {
  let data = @primitives.utf8_bytes("aead round-trip payload").exact_view()
  let armored = @api.encrypt_with_password(data, "swordfish", aead=true)
  let back = @api.decrypt_with_password(armored, "swordfish")
  assert_eq(@utf8.decode_lossy(back.exact_view()), "aead round-trip payload")
  let block = @armor.decode(armored)
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut saw_skesk5 = false
  let mut saw_tag20 = false
  for p in packets {
    if p.tag() == @packet.Skesk {
      let skesk = @packet.SkeskPacket::parse(p.body().exact_view())
      assert_eq(skesk.version(), 5)
      assert_eq(skesk.aead_algo(), @cipher.Ocb.number())
      saw_skesk5 = true
    }
    if p.tag() == @packet.AeadEncData {
      let aead = @packet.AeadPacket::parse(p.body().exact_view())
      assert_eq(aead.version(), 1)
      assert_eq(aead.aead_algo(), @cipher.Ocb.number())
      assert_eq(aead.chunk_octet(), 14)
      saw_tag20 = true
    }
  }
  assert_true(saw_skesk5)
  assert_true(saw_tag20)
}
