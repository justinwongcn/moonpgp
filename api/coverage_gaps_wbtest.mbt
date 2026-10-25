///|
/// Targeted tests for paths the coverage report showed unexercised
/// (consolidation task 1): import-parser branches, password retry error
/// paths, literal-walk chains and small API branches.

///|
/// A PRIVATE certificate may carry a public-only subkey (an export that
/// skipped some secret material): it is binding-validated like any other
/// subkey but contributes no usable secret.
test "private import skips a public-only bound subkey" {
  let a = generate_ed25519_key("A <a@example.com>")
  let now = a.primary.public.creation_time
  let sub = build_eddsa_secret_key_packet(@primitives.random_bytes(32), now)
  let binding = make_binding_signature(
    a.primary,
    a.primary.public,
    sub.public,
    now,
  )
  let w = @packet.Writer::new()
  w.bytes(a.to_bytes().exact_view())
  w.bytes(
    @packet.serialize_packet(
      @packet.PublicSubkey,
      sub.public.to_body().exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, binding.to_body().exact_view()).exact_view(),
  )
  let re = PrivateKey::from_bytes(w.to_bytes().exact_view())
  // Only a's own secret subkey survives; the public-only one is skipped.
  assert_eq(re.subkeys.length(), 1)
  assert_true(
    re.subkeys[0].secret.public
    .key_id()
    .equal(a.subkeys[0].secret.public.key_id()),
  )
}

///|
/// A later certification of the SAME User ID replaces the earlier one
/// (last-wins, gpg's re-certification shape).
test "second certification of the same uid wins on import" {
  let a = generate_ed25519_key("Re <re@example.com>")
  let uid = a.user_id()
  let created = a.primary.public.creation_time
  let first = make_self_signature(a.primary, a.primary.public, uid, created)
  let second = make_self_signature(
    a.primary,
    a.primary.public,
    uid,
    created + 1,
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretKey,
      a.primary.to_body().exact_view(),
    ).exact_view(),
  )
  for sig in [first, second] {
    w.bytes(
      @packet.serialize_packet(
        @packet.UserId,
        @primitives.utf8_bytes(uid).exact_view(),
      ).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
    )
  }
  let re = PrivateKey::from_bytes(w.to_bytes().exact_view())
  assert_eq(re.user_ids.length(), 1)
  assert_eq(re.user_ids[0].self_signature.creation_time(), Some(created + 1))
}

///|
/// Revocation signatures attach during the import walk (and re-export
/// writes them back); their cryptographic validity stays lazy by design.
test "revocation signatures attach and survive re-export" {
  let a = generate_ed25519_key("Rv <rv@example.com>")
  let key_revocation : @packet.SignaturePacket = {
    ..a.self_signature(),
    sig_type: @packet.KeyRevocation,
  }
  let sub_revocation : @packet.SignaturePacket = {
    ..a.subkeys[0].binding,
    sig_type: @packet.SubkeyRevocation,
  }
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretKey,
      a.primary.to_body().exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.UserId,
      @primitives.utf8_bytes(a.user_id()).exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Signature,
      a.self_signature().to_body().exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Signature,
      key_revocation.to_body().exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretSubkey,
      a.subkeys[0].secret.to_body().exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Signature,
      a.subkeys[0].binding.to_body().exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Signature,
      sub_revocation.to_body().exact_view(),
    ).exact_view(),
  )
  let re = PrivateKey::from_bytes(w.to_bytes().exact_view())
  assert_eq(re.revocations.length(), 1)
  assert_true(re.subkeys[0].revocation is Some(_))
  // Re-export writes both revocation packets back.
  let again = PrivateKey::from_bytes(re.to_bytes().exact_view())
  assert_eq(again.revocations.length(), 1)
  assert_true(again.subkeys[0].revocation is Some(_))
}

///|
/// A bare v6 key (no User ID) answers with an empty uid and its Direct
/// Key signature as the key-level self-signature.
test "bare v6 key accessors fall back to the direct signature" {
  let v6 = generate_ed25519_v6_key("Bare <bare@example.com>")
  let bare : PrivateKey = { ..v6, user_ids: [], }
  assert_eq(bare.user_id(), "")
  let pub_half = bare.to_public()
  assert_eq(pub_half.user_id(), "")
  // self_signature falls back to direct_signature (never aborts).
  assert_eq(bare.self_signature().sig_type(), @packet.DirectSignature)
  assert_eq(pub_half.self_signature().sig_type(), @packet.DirectSignature)
}

///|
/// The structural (clock-less) encryption_key selection: last
/// encryption-flagged subkey, else the RSA primary.
test "encryption_key picks the encryption subkey structurally" {
  let key = generate_key("EK <ek@example.com>", bits=2048)
  match key.to_public().encryption_key() {
    Some(k) =>
      assert_true(k.key_id().equal(key.subkeys[0].secret.public.key_id()))
    None => fail("expected the encryption subkey")
  }
  // Without any subkey the RSA primary serves.
  let bare : PrivateKey = { ..key, subkeys: [], }
  match bare.to_public().encryption_key() {
    Some(k) => assert_true(k.key_id().equal(key.primary.public.key_id()))
    None => fail("expected the RSA primary")
  }
}

///|
/// Unlocking an already-unlocked key is a no-op returning the material.
test "unlock on an unlocked key is a no-op" {
  let key = generate_ed25519_key("U <u@example.com>")
  let again = key.unlock("irrelevant")
  assert_eq(again.primary.secret_material, key.primary.secret_material)
}

///|
/// A passphrase that matches no SKESK surfaces the explicit
/// "no SKESK ... matched" error on both the decrypt and the
/// session-key-recovery paths. The fixture uses a deliberately CHEAP S2K
/// (count byte 0 = 1 KiB) so the wrong-passphrase derivations cost
/// nothing — the error paths are identical regardless of the KDF cost.
test "wrong passphrase reports no matching SKESK" {
  let data = @primitives.utf8_bytes("no match")
  let cheap_s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    0,
  )
  let armored = seal_skesk_with_password(data, "right", cheap_s2k)
  let err : String = try {
    let _ = decrypt_with_password(armored, "wrong")
    ""
  } catch {
    e => e.to_string()
  }
  assert_true(err.contains("no SKESK"))
  let err2 : String = try {
    let _ = recover_session_key_with_password(armored, "wrong")
    ""
  } catch {
    e => e.to_string()
  }
  assert_true(err2.contains("no SKESK"))
  // Sanity: the right passphrase still decrypts the cheap fixture.
  assert_eq(decrypt_with_password(armored, "right"), data)
}

///|
/// The v6 password shape (v6 SKESK + v2 SEIPD) round-trips through our
/// own writer and reader (cheap iterated S2K variant).
test "v6 password encryption round-trips" {
  let data = @primitives.utf8_bytes("v6 password roundtrip\n")
  let armored = encrypt_with_password_v6(data, "v6 pass", argon2=false)
  assert_eq(decrypt_with_password(armored, "v6 pass"), data)
}

///|
/// The literal walk handles OnePassSig-first, algo-0 compressed and
/// zip-compressed inner chains through the raw session-key entry point.
test "literal walk handles ops and compressed chains" {
  let key = generate_ed25519_key("W <w@example.com>")
  let data = @primitives.utf8_bytes("walk me")
  let sig = make_document_signature(key.primary, data, @packet.BinaryDocument)
  let literal = @packet.LiteralPacket::binary(data)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let ops = one_pass_sig_for(key.primary, sig, @primitives.Sha256)
  let sk = SessionKey::new(@primitives.random_bytes(32), @primitives.Aes256)
  // 1. OPS first.
  let w1 = @packet.Writer::new()
  w1.bytes(
    @packet.serialize_packet(@packet.OnePassSig, ops.to_body().exact_view()).exact_view(),
  )
  w1.bytes(literal_wire.exact_view())
  // 2. Algo-0 compressed around the literal.
  let w2 = @packet.Writer::new()
  w2.bytes(
    @packet.serialize_packet(
      @packet.Compressed,
      Bytes::from_array([0]).add(literal_wire).exact_view(),
    ).exact_view(),
  )
  // 3. ZIP-compressed around the literal.
  let w3 = @packet.Writer::new()
  w3.bytes(
    @packet.serialize_packet(
      @packet.Compressed,
      Bytes::from_array([1])
      .add(@compress.zip_compress(literal_wire.exact_view()))
      .exact_view(),
    ).exact_view(),
  )
  for inner in [w1.to_bytes(), w2.to_bytes(), w3.to_bytes()] {
    let bc = @primitives.new_block_cipher(sk.algo, sk.key.exact_view())
    let ct = @cipher.seipd_v1_encrypt(bc, inner.exact_view())
    let message = @armor.encode(
      @packet.serialize_packet(
        @packet.Seipd,
        Bytes::from_array([1]).add(ct).exact_view(),
      ).exact_view(),
    )
    assert_eq(decrypt_to_session_key(message, sk), data)
  }
}

///|
/// verify_detached rejects the wrong armor type and a signature armor
/// with no signature packet inside.
test "verify_detached armor shape errors" {
  let key = generate_ed25519_key("V <v@example.com>")
  let data = @primitives.utf8_bytes("x")
  let not_sig = @armor.encode(b"not a packet stream".exact_view())
  let err : String = try {
    let _ = verify_detached(data.exact_view(), not_sig, key.to_public())
    ""
  } catch {
    e => e.to_string()
  }
  assert_true(err.contains("not a signature armor block"))
  // A Signature-labeled armor whose payload holds a non-signature packet:
  // decodes fine, but the walk finds no Signature packet inside.
  let literal_only = @packet.serialize_packet(
    @packet.Literal,
    @packet.LiteralPacket::binary(data).to_body().exact_view(),
  )
  let wrong_payload = @armor.Signature.encode(literal_only.exact_view())
  let err2 : String = try {
    let _ = verify_detached(data.exact_view(), wrong_payload, key.to_public())
    ""
  } catch {
    e => e.to_string()
  }
  assert_true(err2.contains("no signature packet in armor block"))
}

///|
/// decrypt_and_verify with no verifier reports NoVerifier for a signed
/// message (the data still comes back).
test "decrypt_and_verify without a verifier reports NoVerifier" {
  let signer = generate_ed25519_key("S <s@example.com>")
  let recipient = generate_ed25519_key("R <r@example.com>")
  let data = @primitives.utf8_bytes("signed but nobody watching")
  let armored = sign_and_encrypt(data, signer, [recipient.to_public()])
  let (d, status) = decrypt_and_verify(armored, [recipient], None)
  assert_eq(d, data)
  assert_eq(status, NoVerifier)
}

///|
/// Session-key recovery from a v6 PKESK takes the cipher from the v2
/// SEIPD header.
test "recover_session_key_with_key on a v6 message" {
  let v6 = generate_ed25519_v6_key("V6R <v6r@example.com>")
  let data = @primitives.utf8_bytes("v6 session recovery")
  let armored = encrypt_to_recipients(data, [v6.to_public()])
  let sk = recover_session_key_with_key(armored, v6)
  assert_eq(sk.algo, @primitives.Aes256)
  assert_eq(sk.key.length(), 32)
}

///|
/// The private-key decrypt path opens a 4880bis tag-20 AEAD container
/// (the shape gpg 2.4 emits with --force-aead for AEAD-feature
/// recipients) with the PKESK session key, mirroring the password path's
/// lenient GnuPG interop handling.
test "private key decrypt opens a tag-20 aead container" {
  let key = generate_key("T20 <t20@example.com>")
  let session = @primitives.random_bytes(32)
  let data = @primitives.utf8_bytes("tag-20 private-key payload")
  let inner = @packet.serialize_packet(
    @packet.Literal,
    @packet.LiteralPacket::binary(data).to_body().exact_view(),
  )
  let cipher_algo = @primitives.Aes256.number()
  let aead_algo = @cipher.Ocb.number()
  let chunk_octet = 14
  let header5 = Bytes::from_array([
    0xD4,
    1,
    cipher_algo.to_byte(),
    aead_algo.to_byte(),
    chunk_octet.to_byte(),
  ])
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session.exact_view(),
  )
  let iv = @primitives.random_bytes(15)
  let body = @cipher.aead_seal(
    bc,
    @cipher.Ocb,
    header5.exact_view(),
    iv.exact_view(),
    chunk_octet,
    inner.exact_view(),
  )
  let aead : @packet.AeadPacket = {
    version: 1,
    cipher_algo,
    aead_algo,
    chunk_octet,
    iv,
    ciphertext: body,
  }
  let pkesk = create_pkesk(
    key.primary.public,
    session.exact_view(),
    @primitives.Aes256,
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Pkesk, pkesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.AeadEncData, aead.to_body().exact_view()).exact_view(),
  )
  let back = decrypt_binary_with_private_key(w.to_bytes().exact_view(), key)
  assert_eq(@utf8.decode_lossy(back.exact_view()), "tag-20 private-key payload")
}
