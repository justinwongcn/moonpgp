///|
/// RFC 9580 Table 5 assigns signature subpacket type 39 to "Preferred AEAD
/// Ciphersuites"; type 34 is Reserved. Self-generated keys cannot catch a
/// wrong number here — a library that writes 34 and reads 34 keeps every
/// round-trip test green while its preference is invisible to every other
/// implementation (and theirs is invisible to it). These tests pin the
/// wire number from both directions:
///
/// * our v6 writer must emit type 39,
/// * `interop_gocrypto_v6_aead_key.asc` (go-crypto v1.5.2, see
///   `testdata/gen_gocrypto_argon2_vectors.md`) advertises AES-128/OCB
///   first from its v6 Direct Key signature, and that preference must
///   reach the SEIPD v2 header we produce.

///|
test "our v6 keys write Preferred AEAD Ciphersuites as subpacket 39" {
  let public = @api.generate_ed25519_v6_key("Prefs <prefs@test.local>").to_public()
  let packets = @packet.parse_packets(public.to_bytes().exact_view())
  let aead_body : Array[Int] = []
  for p in packets {
    if p.tag() == @packet.Signature {
      let sig = @packet.SignaturePacket::parse(p.body().exact_view())
      if sig.sig_type() == @packet.DirectSignature {
        for sub in sig.hashed_subpackets() {
          if sub.sub_type == 39 {
            aead_body.push(sub.body[0].to_int())
            aead_body.push(sub.body[1].to_int())
          }
        }
      }
    }
  }
  // AES-256/OCB is the most preferred pair of our generated v6 keys.
  assert_eq(aead_body, [9, 2])
}

///|
test "a go-crypto v6 key's AES-128/OCB preference drives our encryption" {
  let key = @api.PrivateKey::from_armored(
    read_testdata("interop_gocrypto_v6_aead_key.asc"),
  )
  let public = key.to_public()
  assert_eq(public.preferred_aead(), [(7, 2)])
  let plaintext = @primitives.utf8_bytes("aes128/ocb v6 for a go-crypto key\n")
  let armored = @api.encrypt_to_recipients(plaintext, [public])
  let block = @armor.decode(armored)
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(block).exact_view(),
  )
  let mut cipher = -1
  for p in packets {
    if p.tag() == @packet.Seipd {
      let seipd = @packet.SeipdPacket::parse(p.body().exact_view())
      assert_eq(seipd.version, 2)
      cipher = seipd.cipher_algo
    }
  }
  // AES-128 (7), not the AES-256 fallback: a v6 ciphersuite below AES-256
  // must also survive the session-key length check on the writer side.
  assert_eq(cipher, 7)
  assert_eq(@api.decrypt_with_private_key(armored, key), plaintext)
}

///|
/// RFC 9580 §13.2 forbids using a symmetric algorithm that is absent from a
/// recipient's preference list, so the choice must satisfy *every*
/// recipient. Ordering the recipients with the AES-256-preferring key first
/// used to select (9,2) — which the go-crypto key (AES-128/OCB only, plus
/// the implicit pair) does not accept.
test "multi-recipient v6 encryption intersects AEAD preferences" {
  let aes256 = @api.generate_ed25519_v6_key("Prefs <aes256@test.local>")
  let aes128 = @api.PrivateKey::from_armored(
    read_testdata("interop_gocrypto_v6_aead_key.asc"),
  )
  assert_eq(aes256.to_public().preferred_aead()[0], (9, 2))
  assert_eq(aes128.to_public().preferred_aead(), [(7, 2)])
  let plaintext = @primitives.utf8_bytes("one common ciphersuite\n")
  let armored = @api.encrypt_to_recipients(plaintext, [
    aes256.to_public(),
    aes128.to_public(),
  ])
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(@armor.decode(armored)).exact_view(),
  )
  let mut cipher = -1
  for p in packets {
    if p.tag() == @packet.Seipd {
      cipher = @packet.SeipdPacket::parse(p.body().exact_view()).cipher_algo
    }
  }
  // AES-128/OCB is the only pair both recipients accept.
  assert_eq(cipher, 7)
  assert_eq(@api.decrypt_with_private_key(armored, aes256), plaintext)
  assert_eq(@api.decrypt_with_private_key(armored, aes128), plaintext)
}
