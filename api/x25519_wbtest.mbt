///|
/// RFC 9580 §5.1.6 defines a **v3** PKESK for X25519 as well: the 32-octet
/// ephemeral key, then a size octet covering "the 1-octet algorithm
/// identifier, if it was passed (in the case of a v3 PKESK packet)" and the
/// wrapped session key. The v3 cleartext cipher octet used to be folded
/// into the wrapped key, so such packets could never be decrypted.
///
/// Table 26 (§10.3.2.1) additionally requires discarding an ESK packet whose
/// version does not align with the payload, which the second test pins.

///|
/// A v3 PKESK to a v6 X25519 subkey, with the cipher octet prepended to the
/// wrapped session key in cleartext.
fn v3_x25519_pkesk(
  enc_key : @packet.PublicKeyPacket,
  session_key : Bytes,
) -> @packet.PkeskPacket raise {
  let recipient = x25519_native_public(enc_key)
  let eph = @pki.x25519_generate()
  let shared = @pki.x25519_shared_secret(
    eph.scalar.exact_view(),
    recipient.exact_view(),
  )
  let kek = x25519_kek(
    eph.public.exact_view(),
    recipient.exact_view(),
    shared.exact_view(),
  )
  // RFC 9580 §5.1.6: no checksum/padding is wrapped — the bare session key
  // goes through AES key wrap, and the cleartext cipher octet is prefixed
  // to the *result* (the size octet covers both).
  let wrapped = @cipher.aes_key_wrap(kek.exact_view(), session_key.exact_view())
  let encrypted = Bytes::from_array([@primitives.Aes256.number().to_byte()]).add(
    wrapped,
  )
  {
    version: 3,
    key_id: enc_key.key_id(),
    key_version: 0,
    fingerprint: Bytes::new(0),
    pub_algo: @packet.X25519,
    encrypted,
    ecdh_ephemeral: eph.public,
  }
}

///|
test "a v3 PKESK to a v6 X25519 key decrypts" {
  let key = generate_ed25519_v6_key("V3 <v3@test.local>")
  let enc_key = key.subkeys[0].secret.public
  let plaintext = @primitives.utf8_bytes("v3 PKESK + v1 SEIPD\n")
  let session_key = @primitives.random_bytes(32)
  let pkesk = v3_x25519_pkesk(enc_key, session_key)
  let literal = @packet.LiteralPacket::binary(plaintext, file_name="m")
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session_key.exact_view(),
  )
  let seipd = @packet.SeipdPacket::v1(
    @cipher.seipd_v1_encrypt(bc, literal_wire.exact_view()).exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Pkesk, pkesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().exact_view()).exact_view(),
  )
  assert_eq(
    decrypt_binary_with_private_key(w.to_bytes().exact_view(), key),
    plaintext,
  )
}

///|
test "a v6 PKESK before a v1 SEIPD is discarded, not mis-decrypted" {
  let key = generate_ed25519_v6_key("Mis <mis@test.local>")
  let enc_key = key.subkeys[0].secret.public
  let plaintext = @primitives.utf8_bytes("mismatched versions\n")
  let session_key = @primitives.random_bytes(32)
  let (eph, wrapped) = x25519_wrap_session_key(
    enc_key,
    session_key.exact_view(),
  )
  let pkesk : @packet.PkeskPacket = {
    version: 6,
    key_id: Bytes::new(0),
    key_version: 6,
    fingerprint: enc_key.fingerprint(),
    pub_algo: @packet.X25519,
    encrypted: wrapped,
    ecdh_ephemeral: eph,
  }
  let literal = @packet.LiteralPacket::binary(plaintext, file_name="m")
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session_key.exact_view(),
  )
  let seipd = @packet.SeipdPacket::v1(
    @cipher.seipd_v1_encrypt(bc, literal_wire.exact_view()).exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Pkesk, pkesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Seipd, seipd.to_body().exact_view()).exact_view(),
  )
  try decrypt_binary_with_private_key(w.to_bytes().exact_view(), key) catch {
    @error.PgpError(msg~) => assert_true(msg.contains("does not align"))
    _ => fail("expected a PgpError for the mismatched ESK version")
  } noraise {
    _ => fail("a v6 PKESK before a v1 SEIPD was accepted")
  }
}
