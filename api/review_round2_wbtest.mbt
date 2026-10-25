///|
/// Regression tests for the 2026-10-25 second review round (N1-N9).
/// Whitebox: they reach the import validator, internal signature
/// builders and `verify_signature_packet` directly.

///|
/// N1: a subkey packet injected into a certificate without any
/// SubkeyBinding signature must be rejected at import — before the fix
/// it was accepted and treated as encryption-capable, letting an
/// attacker who forwards a tampered public key receive the mail.
test "N1: subkey without a binding signature is rejected on import" {
  let a = generate_ed25519_key("Alice <alice@example.com>")
  let b = generate_ed25519_key("Mallory <mallory@example.com>")
  // Mallory's subkey packet, appended to Alice's public certificate with
  // no binding of any kind.
  let mut extra : Bytes? = None
  for p in @packet.parse_packets(b.to_public().to_bytes().exact_view()) {
    if p.tag() == @packet.PublicSubkey {
      extra = Some(p.body())
    }
  }
  let w = @packet.Writer::new()
  w.bytes(a.to_public().to_bytes().exact_view())
  w.bytes(
    @packet.serialize_packet(@packet.PublicSubkey, extra.unwrap().exact_view()).exact_view(),
  )
  let raised = try {
    let _ = PublicKey::from_bytes(w.to_bytes().exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // The private-key import path shares the validation.
  let w2 = @packet.Writer::new()
  w2.bytes(a.to_bytes().exact_view())
  w2.bytes(
    @packet.serialize_packet(
      @packet.SecretSubkey,
      b.subkeys[0].secret.to_body().exact_view(),
    ).exact_view(),
  )
  let raised2 = try {
    let _ = PrivateKey::from_bytes(w2.to_bytes().exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
}

///|
/// A document signature issued by a specific subkey (helper for N2/N7).
fn subkey_document_sig(
  secret : @packet.SecretKeyPacket,
  data : BytesView,
) -> @packet.SignaturePacket raise {
  let now = @primitives.unix_now().to_int()
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(now),
    key_flags_subpacket(0x02),
    {
      critical: false,
      sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
      body: secret.public.key_id(),
    },
  ]
  let sig : @packet.SignaturePacket = {
    version: 4,
    sig_type: @packet.BinaryDocument,
    pub_algo: secret.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: [],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: Bytes::new(0),
    sig_params: [],
  }
  let digest = document_hash(sig, data, @packet.BinaryDocument)
  finish_signature(sig, secret, @primitives.Sha256, digest.exact_view())
}

///|
/// N2: a certificate with an encryption subkey AND a signing subkey keeps
/// both; encryption selection honours each subkey's own flags, and a
/// signature from the signing subkey verifies against the certificate.
test "N2: multiple subkeys are kept, paired, and role-selected" {
  let a = generate_ed25519_key("Multi <multi@example.com>")
  let created = a.primary.public.creation_time
  // A signing-only subkey, bound after the encryption subkey (so a
  // last-wins single-slot model would have dropped the encryption one).
  let signing = build_eddsa_secret_key_packet(
    @primitives.random_bytes(32),
    created,
  )
  let binding = make_binding_signature(
    a.primary,
    a.primary.public,
    signing.public,
    created,
    key_flags=0x02,
    subkey_secret=signing,
  )
  let multi : PrivateKey = {
    ..a,
    subkeys: [
      a.subkeys[0],
      SecretSubkeyCert::{ secret: signing, binding, revocation: None, },
    ],
  }
  // Import keeps BOTH subkeys, each with its own binding.
  let re = PrivateKey::from_bytes(multi.to_bytes().exact_view())
  assert_eq(re.subkeys.length(), 2)
  let pk = re.to_public()
  // Encryption selection picks the encryption-flagged subkey (the first),
  // not merely the last one on the wire.
  let now = @primitives.unix_now()
  let enc = pk.encryption_packet_at(now).unwrap()
  assert_true(enc.key_id().equal(pk.subkeys[0].key.key_id()))
  // A document signature from the signing subkey verifies and lands Ok.
  let data = @primitives.utf8_bytes("signed by the signing subkey")
  let sig = subkey_document_sig(re.subkeys[1].secret, data.exact_view())
  assert_eq(verify_signature_packet(sig, data.exact_view(), pk), Ok)
}

///|
/// N3: persona (0x11) and casual (0x12) self-certifications bind a User
/// ID exactly like positive ones — keys certified that way must import.
test "N3: persona and casual self-certifications import" {
  let key = generate_ed25519_key("P <p@example.com>")
  let uid = key.user_id()
  let created = key.primary.public.creation_time
  for cert_type in [@packet.PersonaCertification, @packet.CasualCertification] {
    let cert = make_self_signature(
      key.primary,
      key.primary.public,
      uid,
      created,
      cert_type~,
    )
    let mixed : PrivateKey = {
      ..key,
      user_ids: [UserIdBinding::{ user_id: uid, self_signature: cert, }],
    }
    let re = PrivateKey::from_bytes(mixed.to_bytes().exact_view())
    assert_eq(re.user_ids[0].self_signature.sig_type(), cert_type)
  }
}

///|
/// N4: a message sealed to two passphrases decrypts with either — the
/// SKESK retry spans the payload decryption, so a wrong passphrase whose
/// v4 SKESK unwraps to plausible garbage still falls through to the next
/// SKESK at the SEIPD integrity check.
test "N4: two-password message decrypts with either passphrase" {
  let data = @primitives.utf8_bytes("two password recipients")
  let encrypt = pgp().encryption().password("alpha").password("beta").finish()
  let armored = encrypt(data)
  assert_eq(decrypt_with_password(armored, "alpha"), data)
  assert_eq(decrypt_with_password(armored, "beta"), data)
  // Decryption with a list of candidate passphrases tries them all.
  let decrypt = pgp().decryption().password("wrong").password("beta").finish()
  match decrypt(armored) {
    Data(d) => assert_eq(d, data)
    _ => fail("expected Data with the second passphrase")
  }
}

///|
/// N5: with several decryption keys AND a verifier configured, the
/// builder still verifies — the verifier used to be silently dropped.
test "N5: builder multi-key decryption still consults the verifier" {
  let signer = generate_ed25519_key("S <s@example.com>")
  let recipient = generate_ed25519_key("R <r@example.com>")
  let other = generate_ed25519_key("O <o@example.com>")
  let data = @primitives.utf8_bytes("multi-key builder payload")
  let armored = sign_and_encrypt(data, signer, [recipient.to_public()])
  // `other` cannot decrypt; `recipient` can; the signature by `signer`
  // must still be checked against the configured verifier.
  let decrypt = pgp()
    .decryption()
    .decryption_key(other)
    .decryption_key(recipient)
    .verification_key(signer.to_public())
    .finish()
  match decrypt(armored) {
    Verified(d) => assert_eq(d, data)
    _ => fail("expected Verified, not Data/SignatureError")
  }
}

///|
/// N7: a cryptographically valid subkey signature is not `Ok` when the
/// PRIMARY key has expired — a subkey exists only as part of its
/// certificate.
test "N7: subkey signature of an expired primary is Expired" {
  let key = generate_ed25519_key("Exp <exp@example.com>")
  let now32 = @primitives.unix_now().to_int()
  // Backdate the primary one hour and give its self-signature a
  // one-minute lifetime (lifecycle reads subpackets only, so no
  // re-signing is needed for this whitebox check).
  let backdated : @packet.PublicKeyPacket = {
    ..key.primary.public,
    creation_time: now32 - 3600,
  }
  let old = key.self_signature()
  let expired_self : @packet.SignaturePacket = {
    ..old,
    hashed_subpackets: [
      ..old.hashed_subpackets,
      {
        critical: false,
        sub_type: @packet.SIGSUB_KEY_EXPIRATION_TIME,
        body: Bytes::from_array([0, 0, 0, 60]),
      },
    ],
  }
  let pk : PublicKey = {
    primary: backdated,
    user_ids: [
      UserIdBinding::{ user_id: key.user_id(), self_signature: expired_self, },
    ],
    direct_signature: None,
    subkeys: key.to_public().subkeys,
    revocations: [],
  }
  let now = @primitives.unix_now()
  assert_true(pk.is_expired(now))
  assert_eq(lifecycle_status(expired_self, pk, Some(pk.subkeys[0])), Expired)
  // The primary path (comp = None) reports Expired as before.
  assert_eq(lifecycle_status(expired_self, pk, None), Expired)
}

///|
/// N8: v5 (RFC 4880bis draft) key packets are rejected at the parse
/// layer instead of parsing and failing later at first use.
test "N8: v5 draft key packets are rejected at parse" {
  let raised = try {
    let _ = @packet.PublicKeyPacket::parse(Bytes::from_array([5]).exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
/// N9: `sign_and_encrypt` and the encryption builder honour `file_name`
/// for the literal packet instead of hardcoding "message.txt".
test "N9: sign_and_encrypt honors file_name" {
  let signer = generate_ed25519_key("FN <fn@example.com>")
  let recipient = generate_ed25519_key("FR <fr@example.com>")
  let data = @primitives.utf8_bytes("named attachment")
  let armored = sign_and_encrypt(
    data,
    signer,
    [recipient.to_public()],
    file_name="report.bin",
  )
  let via_builder = pgp()
  .encryption()
  .file_name("builder.bin")
  .sign_with(signer)
  .recipient(recipient.to_public())
  .finish()(data)
  for msg in [armored, via_builder] {
    let block = @armor.decode(msg)
    let packets = @packet.parse_packets(
      @armor.ArmorBlock::data(block).exact_view(),
    )
    let inner = decrypt_inner_with_key(packets, recipient).unwrap()
    let mut seen : String? = None
    for p in @packet.parse_packets(inner.exact_view()) {
      if p.tag() == @packet.Literal {
        seen = Some(
          @packet.LiteralPacket::parse(p.body().exact_view()).file_name(),
        )
      }
    }
    assert_eq(
      seen.unwrap(),
      if msg == armored {
        "report.bin"
      } else {
        "builder.bin"
      },
    )
  }
}
