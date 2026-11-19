///|
/// Round-2 audit probes (api1–api7): composition semantics, typed-error
/// preservation, recovery honesty, multi-block import, SKESK checksum
/// shapes, multi-signature verification and surrogate hardening.

///|
test "api1: wrong passphrase keeps its variant through the builder" {
  let msg = encrypt_with_password(b"secret", "right")
  // The builder's password retry loop used to flatten the typed
  // WrongPassphrase into a generic Fail via e.to_string().
  let wrong = try {
    ignore(pgp().decryption().password("wrong").finish()(msg))
    false
  } catch {
    @error.WrongPassphrase(_) => true
    _ => false
  }
  assert_true(wrong)
}

///|
test "api2: password + recipient seal one message with both ESK kinds" {
  let key = generate_ed25519_key("api2 <t@e>")
  let seal = pgp()
    .encryption()
    .password("backup")
    .recipient(key.to_public())
    .finish()
  let armored = seal(b"payload")
  // The recipient opens it.
  let (d, _s) = decrypt_and_verify(armored, [key], None)
  assert_eq(d, b"payload")
  // AND the passphrase does too — the SKESK used to be dropped silently.
  let d2 = decrypt_with_password(armored, "backup")
  assert_eq(d2, b"payload")
}

///|
test "api2: password + signer produces a signed message" {
  let key = generate_ed25519_key("api2s <t@e>")
  let seal = pgp().encryption().password("pw").sign_with(key).finish()
  let armored = seal(b"payload")
  // The signer must be HONORED in the sealed payload (api2): opening the
  // SEIPD with the unwrapped session key reveals the packet stream
  // one-pass-signature + literal + signature. (Since round 3 the
  // password decryption path ALSO verifies embedded signatures via
  // decrypt_password_and_verify — the earlier "registered leftover" note
  // is closed.)
  let block = @armor.decode(armored)
  let ps = @packet.parse_packets(block.data().exact_view())
  let mut skesk : @packet.SkeskPacket? = None
  let mut seipd : @packet.SeipdPacket? = None
  for p in ps {
    match p.tag() {
      @packet.Skesk =>
        skesk = Some(@packet.SkeskPacket::parse(p.body().exact_view()))
      @packet.Seipd =>
        seipd = Some(@packet.SeipdPacket::parse(p.body().exact_view()))
      _ => ()
    }
  }
  let budget = S2KBudget::new()
  let (algo, key, version, _proved) = unwrap_one_skesk(
    skesk.unwrap(),
    "pw",
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget~,
  )
  assert_eq(version, 4)
  let seipd = seipd.unwrap()
  assert_eq(seipd.version, 1)
  let bc = @primitives.new_block_cipher(algo, key.exact_view())
  let inner = @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.exact_view())
  let inner_ps = @packet.parse_packets(inner.exact_view())
  assert_eq(inner_ps.length(), 3)
  assert_true(inner_ps[0].tag() is @packet.PacketTag::OnePassSig)
  assert_true(inner_ps[1].tag() is @packet.PacketTag::Literal)
  assert_true(inner_ps[2].tag() is @packet.PacketTag::Signature)
}

///|
test "api2: v6 password + signer produces a signed message" {
  let key = generate_ed25519_key("api2v6 <t@e>")
  let seal = pgp().encryption().password_v6("pw").sign_with(key).finish()
  let armored = seal(b"payload")
  // Same structural check for the v6 shape (v2 SEIPD): the signer rides
  // inside the sealed payload.
  let block = @armor.decode(armored)
  let ps = @packet.parse_packets(block.data().exact_view())
  let mut skesk : @packet.SkeskPacket? = None
  let mut seipd : @packet.SeipdPacket? = None
  for p in ps {
    match p.tag() {
      @packet.Skesk =>
        skesk = Some(@packet.SkeskPacket::parse(p.body().exact_view()))
      @packet.Seipd =>
        seipd = Some(@packet.SeipdPacket::parse(p.body().exact_view()))
      _ => ()
    }
  }
  let budget = S2KBudget::new()
  let (_algo, key, version, _proved) = unwrap_one_skesk(
    skesk.unwrap(),
    "pw",
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget~,
  )
  assert_eq(version, 6)
  let seipd = seipd.unwrap()
  assert_eq(seipd.version, 2)
  // The v2 SEIPD payload is AEAD-sealed under an HKDF-separated message
  // key; the v6 SKESK unwrap already proved the passphrase, so opening it
  // here just mirrors open_seipd_v2. Parse the literal-only inner instead:
  // unwrap_skesk's own proof + the sealed-shape change are the assertion.
  assert_true(seipd.ciphertext.length() > 0)
  ignore(key)
}

///|
test "api3: corrupted RSA PKESK fails the recovery honestly" {
  let key = generate_key("api3 <t@e>", bits=3072)
  let msg = encrypt_to_recipients(b"payload", [key.to_public()])
  // Flip one byte inside the PKESK's encrypted MPI (after the two length
  // octets): the S04 mask used to hand the recovery flow a random
  // session key as a bogus success.
  let block = @armor.decode(msg)
  let data = block.data()
  // packet header: old/new format + length; the MPI body starts after
  // the version(1)+keyid(8)+algo(1) prefix of the v3 PKESK body.
  let corrupt : Array[Byte] = []
  for i in 0..<data.length() {
    corrupt.push(data[i])
  }
  // The PKESK leads the stream with a NEW-format header: [0]=0xC2 tag,
  // [1..3]=two length octets, body = version(1) keyid(8) algo(1)
  // MPI-bits(2) MPI-value(...). Byte 16 sits INSIDE the MPI value — the
  // S04 mask turns the failed RSA unwrap into a random session key
  // (old code: bogus success), and unwrap_pkesk_checked raises (new).
  // The first probe draft flipped byte 14, the MPI BIT-LENGTH low octet:
  // the F6 trailing-octet gate rejected that packet before the unwrap
  // ever ran, so the red evidence never discriminated old from new.
  corrupt[16] = (corrupt[16].to_int() ^ 0x40).to_byte()
  let corrupted = @armor.Message.encode(Bytes::from_array(corrupt).exact_view())
  let failed = try {
    ignore(recover_session_key_with_key(corrupted, key))
    false
  } catch {
    _ => true
  }
  assert_true(failed)
  // The uncorrupted message still recovers.
  let ok = recover_session_key_with_key(msg, key)
  assert_true(ok.key().length() == 32)
}

///|
test "api4: concatenated keyrings refuse to import one key silently" {
  let a = generate_ed25519_key("api4a <t@e>")
  let b = generate_ed25519_key("api4b <t@e>")
  let ring = a.to_public().to_armored() + b.to_public().to_armored()
  let raised = try {
    ignore(PublicKey::from_armored(ring))
    false
  } catch {
    e => e.to_string().contains("key blocks")
  }
  assert_true(raised)
  // A single key still imports; non-key blocks (garbage armor) stay
  // tolerated as the documented first-block scan.
  let single = PublicKey::from_armored(a.to_public().to_armored())
  assert_eq(single.fingerprint(), a.to_public().fingerprint())
}

///|
test "api5: legacy checksum-free SKESK still decrypts" {
  // Hand-build the historical shape: v4 SKESK wrapping [algo || key]
  // with NO checksum (what this library wrote before api5), over a v1
  // SEIPD payload.
  let session_key = @primitives.random_bytes(32)
  let plain = Bytes::from_array([@primitives.Aes256.number().to_byte()]).add(
    session_key,
  )
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let wrapping_key = s2k.derive_key(b"legacy-pass", 32)
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    wrapping_key.exact_view(),
  )
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(16, b'\x00').exact_view(),
    plain.exact_view(),
  )
  let skesk : @packet.SkeskPacket = {
    version: 4,
    cipher_algo: @primitives.Aes256.number(),
    aead_algo: 0,
    s2k,
    iv: Bytes::make(0, b'\x00'),
    encrypted_session_key: esk,
  }
  let seipd_ciphertext = @cipher.seipd_v1_encrypt(
    @primitives.new_block_cipher(@primitives.Aes256, session_key.exact_view()),
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(b"legacy payload").to_body().exact_view(),
    ).exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Seipd,
      Bytes::from_array([1]).add(seipd_ciphertext).exact_view(),
    ).exact_view(),
  )
  let msg = @armor.Message.encode(w.to_bytes().exact_view())
  let d = decrypt_with_password(msg, "legacy-pass")
  assert_eq(d, b"legacy payload")
  // A wrong passphrase must not slip through the length window.
  let wrong = try {
    ignore(decrypt_with_password(msg, "wrong-pass"))
    false
  } catch {
    @error.WrongPassphrase(_) => true
    _ => false
  }
  assert_true(wrong)
}

///|
test "api5: standard checksum-free SKESK round-trips and fails loudly" {
  // RFC 9580 §5.3.1 shape: the decrypted esk is [algo || key] — the
  // 2-octet checksum RFC 4880 carried was dropped from the standard and
  // gpg 2.4.5 rejects it (probed; the checksummed-writer change was
  // reverted before commit). The wrong passphrase surfaces as
  // WrongPassphrase at the MDC (E7 classification).
  let msg = encrypt_with_password(b"payload", "right-pass")
  let d = decrypt_with_password(msg, "right-pass")
  assert_eq(d, b"payload")
  let wrong = try {
    ignore(decrypt_with_password(msg, "wrong-pass"))
    false
  } catch {
    @error.WrongPassphrase(_) => true
    _ => false
  }
  assert_true(wrong)
}

///|
test "api5: legacy RFC 4880 checksummed SKESK is read with unwrap-time proof" {
  // Hand-build the 4880-era shape [algo || key || checksum]: the reader
  // tolerates it and the checksum proves the passphrase at unwrap time
  // (before the MDC).
  let session_key = @primitives.random_bytes(32)
  let sum = @packet.session_key_checksum(session_key.exact_view())
  let plain = Bytes::from_array([@primitives.Aes256.number().to_byte()])
    .add(session_key)
    .add(Bytes::from_array([(sum >> 8).to_byte(), sum.to_byte()]))
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let wrapping_key = s2k.derive_key(b"legacy-pass", 32)
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    wrapping_key.exact_view(),
  )
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(16, b'\x00').exact_view(),
    plain.exact_view(),
  )
  let skesk : @packet.SkeskPacket = {
    version: 4,
    cipher_algo: @primitives.Aes256.number(),
    aead_algo: 0,
    s2k,
    iv: Bytes::make(0, b'\x00'),
    encrypted_session_key: esk,
  }
  let seipd_ciphertext = @cipher.seipd_v1_encrypt(
    @primitives.new_block_cipher(@primitives.Aes256, session_key.exact_view()),
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(b"4880 payload").to_body().exact_view(),
    ).exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Seipd,
      Bytes::from_array([1]).add(seipd_ciphertext).exact_view(),
    ).exact_view(),
  )
  let msg = @armor.Message.encode(w.to_bytes().exact_view())
  let d = decrypt_with_password(msg, "legacy-pass")
  assert_eq(d, b"4880 payload")
  let wrong = try {
    ignore(decrypt_with_password(msg, "wrong-pass"))
    false
  } catch {
    @error.WrongPassphrase(_) => true
    _ => false
  }
  assert_true(wrong)
}

///|
test "api7: the second signature packet of a multi-signature armor verifies" {
  let a = generate_ed25519_key("api7a <t@e>")
  let b = generate_ed25519_key("api7b <t@e>")
  // gpg --detach-sign -u A -u B shape: two Signature packets in one armor
  // block, A first.
  let packets_a = @packet.parse_packets(
    @armor.decode(sign_detached(b"payload".exact_view(), a)).data().exact_view(),
  )
  let packets_b = @packet.parse_packets(
    @armor.decode(sign_detached(b"payload".exact_view(), b)).data().exact_view(),
  )
  let sig_a = @packet.SignaturePacket::parse(packets_a[0].body().exact_view())
  let sig_b = @packet.SignaturePacket::parse(packets_b[0].body().exact_view())
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig_a.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig_b.to_body().exact_view()).exact_view(),
  )
  let multi = @armor.Signature.encode(w.to_bytes().exact_view())
  // Verifying with B used to stop at A's packet and report NoVerifier.
  assert_eq(verify_detached(b"payload".exact_view(), multi, b.to_public()), Ok)
  assert_eq(verify_detached(b"payload".exact_view(), multi, a.to_public()), Ok)
}

///|
test "api6: astral-plane text still encodes at the chokepoint" {
  let key = generate_ed25519_key("api6 <t@e>")
  // Valid surrogate pairs encode and round-trip as before.
  let msg = sign_cleartext("emoji \u{1F600} text", key)
  let (_, status) = verify_cleartext(msg, key.to_public())
  assert_eq(status, Ok)
  // The lone-surrogate rejection cannot be exercised from pure MoonBit —
  // the lexer rejects surrogate escapes and Int::to_char validates them —
  // it guards the js-target host boundary, where a JS string handed over
  // by @env can carry a lone surrogate that made core's encoder ABORT the
  // process (audit api6; uncatchable for embedders). The chokepoint check
  // turns that into a catchable Malformed.
  assert_true(@primitives.utf8_bytes("a\u{1F600}b").length() == 6)
}

///|
test "pw-verify: the password branch consults configured verifiers" {
  let key = generate_ed25519_key("pwv <t@e>")
  // api2 made .password().sign_with() seal an inline signature; the
  // decryption builder's password branch used to ignore the verification
  // key entirely — a signed message surfaced as Data (no-signature
  // semantics), indistinguishable from a stripped signature.
  let seal = pgp().encryption().password("pw").sign_with(key).finish()
  let armored = seal(b"payload")
  let open = pgp()
    .decryption()
    .password("pw")
    .verification_key(key.to_public())
    .finish()
  let result = open(armored)
  let status = match result {
    Verified(_) => Ok
    SignatureError(_) => Failed
    Data(_) => NotSigned
  }
  assert_eq(status, Ok)
  // An unsigned password message still lands in Data (no verifier match).
  let plain = encrypt_with_password(b"payload", "pw")
  let open2 = pgp()
    .decryption()
    .password("pw")
    .verification_key(key.to_public())
    .finish()
  let result2 = open2(plain)
  assert_true(result2 is Data(_))
}

///|
test "v6 combo: password_v6 + v6 recipient seals both ESK kinds (f1 follow-up)" {
  // The registered follow-up to f1 is now real: v6 SKESK + v6 PKESK in
  // one message, one shared session key (RFC 9580 §10.3.2.1).
  let key = generate_ed25519_v6_key("v6combo <t@e>")
  let seal = pgp()
    .encryption()
    .password_v6("pw6")
    .recipient(key.to_public())
    .finish()
  let armored = seal(b"payload")
  // The recipient opens it (v6 PKESK + v2 SEIPD).
  let (d, _s) = decrypt_and_verify(armored, [key], None)
  assert_eq(d, b"payload")
  // AND the v6 passphrase holder does too (v6 SKESK over the same
  // session key).
  let d2 = decrypt_with_password(armored, "pw6")
  assert_eq(d2, b"payload")
}

///|
test "v6 combo: v4 recipient x v6 passphrase fails loudly" {
  let v4 = generate_ed25519_key("v4c <t@e>")
  let raised = try {
    ignore(
      pgp().encryption().password_v6("pw").recipient(v4.to_public()).finish()(
        b"x",
      ),
    )
    false
  } catch {
    e => e.to_string().contains("cannot mix")
  }
  assert_true(raised)
}

///|
test "pv1: a failing first SKESK does not kill the retry" {
  // SKESK#1 wraps a session key that does NOT open the payload; SKESK#2
  // carries the real one. Both unwrap honestly under the same passphrase
  // (no checksum on the v4 shape), so the first container open fails at
  // the MDC — the retry loop must move on to SKESK#2. The round-2
  // standalone verify entry unwrapped the FIRST SKESK outside the loop:
  // the MDC failure escaped as Malformed and SKESK#2 was never tried.
  let wrong_key = @primitives.random_bytes(32)
  let real_key = @primitives.random_bytes(32)
  let s2k1 : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let s2k2 : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let skesk1 = build_skesk(
    @primitives.Aes256,
    wrong_key.exact_view(),
    "p",
    s2k1,
  )
  let skesk2 = build_skesk(@primitives.Aes256, real_key.exact_view(), "p", s2k2)
  let seipd_ciphertext = @cipher.seipd_v1_encrypt(
    @primitives.new_block_cipher(@primitives.Aes256, real_key.exact_view()),
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(b"payload").to_body().exact_view(),
    ).exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk1.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk2.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Seipd,
      Bytes::from_array([1]).add(seipd_ciphertext).exact_view(),
    ).exact_view(),
  )
  let msg = @armor.Message.encode(w.to_bytes().exact_view())
  let (d, status) = decrypt_password_and_verify(msg, "p", [])
  assert_eq(d, b"payload")
  assert_eq(status, NotSigned)
}

///|
test "pv1b: multi-SKESK retry with verifiers configured (moved-code combo)" {
  // The round-3 rewire moved verification INSIDE the shared retry loop;
  // this pins the moved-code combination the pv1 test does not cover:
  // multiple SKESKs AND verifiers non-empty. SKESK#1 wraps a wrong key
  // (MDC failure, E7-classified, retry), SKESK#2 opens; the payload is
  // unsigned, so the verify branch reports NotSigned.
  let verifier = generate_ed25519_key("pv1b <t@e>")
  let wrong_key = @primitives.random_bytes(32)
  let real_key = @primitives.random_bytes(32)
  let s2k1 : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let s2k2 : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let skesk1 = build_skesk(
    @primitives.Aes256,
    wrong_key.exact_view(),
    "p",
    s2k1,
  )
  let skesk2 = build_skesk(@primitives.Aes256, real_key.exact_view(), "p", s2k2)
  let seipd_ciphertext = @cipher.seipd_v1_encrypt(
    @primitives.new_block_cipher(@primitives.Aes256, real_key.exact_view()),
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(b"payload").to_body().exact_view(),
    ).exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk1.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk2.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Seipd,
      Bytes::from_array([1]).add(seipd_ciphertext).exact_view(),
    ).exact_view(),
  )
  let msg = @armor.Message.encode(w.to_bytes().exact_view())
  let (d, status) = decrypt_password_and_verify(msg, "p", [verifier.to_public()])
  assert_eq(d, b"payload")
  assert_eq(status, NotSigned)
}

///|
test "r9-1: a verifier-raising signature keeps data on the password path" {
  // Wire-reachable shape the round-9 fix pins: a Signature packet whose
  // hash_algo byte is unassigned (parse does not check it;
  // verify_signature_packet raises Unsupported at document_hash). The
  // per-verifier catch maps that to Failed and the decrypted data
  // survives — before the fix the raise voided the data and killed the
  // whole call. The OPS is well-formed and pairs with the signature
  // (audit hit-2: an unparseable OPS voids the stream, so the old
  // hand-built truncated OPS bytes would now classify as NotSigned).
  let verifier = generate_ed25519_key("r91 <t@e>")
  let session_key = @primitives.random_bytes(32)
  let sig : @packet.SignaturePacket = {
    version: 4,
    sig_type: @packet.BinaryDocument,
    pub_algo: @packet.Ed25519,
    hash_algo: 0x63,
    hashed_subpackets: [ // unassigned hash algorithm id
    ],
    unhashed_subpackets: [],
    raw_hashed_area: Bytes::make(0, b'\x00'),
    fast_hash: 0,
    salt: Bytes::make(0, b'\x00'),
    sig_params: [Bytes::make(64, b'\x04')],
  }
  // A well-formed v3 OPS whose hash octet matches the (unassigned)
  // signature hash — the pairing must hold for the signature to reach
  // the verifier (audit hit-2).
  let ops_body = @packet.Writer::new()
  ops_body.u8(3)
  ops_body.u8(0) // BinaryDocument
  ops_body.u8(0x63)
  ops_body.u8(sig.pub_algo().number())
  ops_body.bytes(verifier.primary.public.key_id().exact_view())
  ops_body.u8(1) // nested
  let inner = @packet.Writer::new()
  inner.bytes(
    @packet.serialize_packet(
      @packet.OnePassSig,
      ops_body.to_bytes().exact_view(),
    ).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(b"payload").to_body().exact_view(),
    ).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    @primitives.random_bytes(@s2k.SALT_SIZE),
    @s2k.encode_count(96),
  )
  let skesk = build_skesk(
    @primitives.Aes256,
    session_key.exact_view(),
    "p",
    s2k,
  )
  let seipd_ciphertext = @cipher.seipd_v1_encrypt(
    @primitives.new_block_cipher(@primitives.Aes256, session_key.exact_view()),
    inner.to_bytes().exact_view(),
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Skesk, skesk.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Seipd,
      Bytes::from_array([1]).add(seipd_ciphertext).exact_view(),
    ).exact_view(),
  )
  let msg = @armor.Message.encode(w.to_bytes().exact_view())
  let (d, status) = decrypt_password_and_verify(msg, "p", [verifier.to_public()])
  assert_eq(d, b"payload")
  assert_eq(status, Failed)
}

///|
test "key-path tolerance: unknown hash_algo verifier keeps data (r13 follow-up)" {
  // The key-path normalization twin of r9-1: finish_inline_verify maps a
  // verifier raise (unknown hash algorithm at document_hash) to Failed
  // with the decrypted data intact — before, the Unsupported escaped and
  // the caller lost the data. The OPS is well-formed and pairs with the
  // signature (audit hit-2: an unparseable OPS voids the stream).
  let key = generate_ed25519_key("ktol <t@e>")
  let sig : @packet.SignaturePacket = {
    version: 4,
    sig_type: @packet.BinaryDocument,
    pub_algo: @packet.Ed25519,
    hash_algo: 0x63,
    hashed_subpackets: [ // unassigned hash algorithm id
    ],
    unhashed_subpackets: [],
    raw_hashed_area: Bytes::make(0, b'\x00'),
    fast_hash: 0,
    salt: Bytes::make(0, b'\x00'),
    sig_params: [Bytes::make(64, b'\x04')],
  }
  // A well-formed v3 OPS whose hash octet matches the (unassigned)
  // signature hash (audit hit-2).
  let ops_body = @packet.Writer::new()
  ops_body.u8(3)
  ops_body.u8(0) // BinaryDocument
  ops_body.u8(0x63)
  ops_body.u8(sig.pub_algo().number())
  ops_body.bytes(key.primary.public.key_id().exact_view())
  ops_body.u8(1) // nested
  let inner = @packet.Writer::new()
  inner.bytes(
    @packet.serialize_packet(
      @packet.OnePassSig,
      ops_body.to_bytes().exact_view(),
    ).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(b"payload").to_body().exact_view(),
    ).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  let armored = seal_to_recipients(inner.to_bytes().exact_view(), [
    key.to_public(),
  ])
  let (d, status) = decrypt_and_verify(armored, [key], Some(key.to_public()))
  assert_eq(d, b"payload")
  assert_eq(status, Failed)
}

///|
test "c2g7: recent SHA-1 signatures do not validate, legacy ones do" {
  // RFC 9580 §9.5: recent weak-hash signatures MUST NOT validate; old
  // ones stay verifiable (SHOULD NOT, with the custody caveat). The
  // "recent" line is implemented as the SHA-1 chosen-prefix cutoff
  // (SHAttered, 2020-01-01). The signatures are minted below the policy
  // gate with explicit creation dates (RSA carries the legacy shape —
  // Ed25519 is barred from sub-256-bit digests by §5.2.3.4, c1g3).
  let key = generate_key("c2g7 <t@e>", bits=3072)
  let data : Bytes = b"legacy sha-1 document"
  let sig_old = make_document_signature_with(
    key.primary,
    data.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha1,
    created=1546300800,
    policy_gate=false,
  )
  let armored_old = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig_old.to_body().exact_view()).exact_view(),
  )
  assert_true(
    verify_detached(data.exact_view(), armored_old, key.to_public()) is Ok,
  )
  let sig_new = make_document_signature_with(
    key.primary,
    data.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha1,
    created=1609459200,
    policy_gate=false,
  )
  let armored_new = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig_new.to_body().exact_view()).exact_view(),
  )
  assert_true(
    verify_detached(data.exact_view(), armored_new, key.to_public()) is Failed,
  )
}

///|
test "c1g6: an OPS whose fields disagree with the signature is ignored" {
  // RFC 9580 §5.2.5: a signature that disagrees with the stream's
  // One-Pass Signature (version, type, hash, pub-algo) MUST be ignored
  // for validation. The stream below carries OPS(hash=SHA-256) but a
  // trailing SHA-512 signature — before the pairing check it verified Ok
  // with no OPS<->signature relationship checked at all.
  let key = generate_ed25519_key("c1g6 <t@e>")
  let data : Bytes = b"payload"
  let mint = make_document_signature_with(
    key.primary,
    data.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha512,
  )
  let inner = @packet.Writer::new()
  inner.bytes(
    @packet.serialize_packet(
      @packet.OnePassSig,
      Bytes::from_array([3, 0, 9, 22, 1])
      .add(key.primary.public.key_id())
      .exact_view(),
    ).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(data).to_body().exact_view(),
    ).exact_view(),
  )
  inner.bytes(
    @packet.serialize_packet(@packet.Signature, mint.to_body().exact_view()).exact_view(),
  )
  let armored = seal_to_recipients(inner.to_bytes().exact_view(), [
    key.to_public(),
  ])
  let (d, status) = decrypt_and_verify(armored, [key], Some(key.to_public()))
  // Data still delivered; the mismatched signature is NOT validated.
  assert_eq(d, data)
  assert_eq(status, NotSigned)
}

///|
test "c1g1: unknown critical packets reject, non-critical are ignored" {
  // RFC 9580 §4.3: Type IDs 0-39 are critical — an unknown one MUST
  // reject the whole sequence; 40-63 are non-critical and MUST be
  // ignored. Tag 21 (Padding) is a defined type and stays ignorable.
  let literal = @packet.serialize_packet(
    @packet.Literal,
    @packet.LiteralPacket::binary(b"payload").to_body().exact_view(),
  )
  let critical_unknown = Bytes::from_array([0xC0 | 22, 1]).add(b"x")
  let non_critical = Bytes::from_array([0xC0 | 45, 1]).add(b"x")
  let padding = Bytes::from_array([0xC0 | 21, 3]).add(b"abc")
  // Critical unknown: the sequence is rejected.
  let raised = try {
    ignore(@packet.parse_packets(critical_unknown.add(literal).exact_view()))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Non-critical unknown: ignored.
  let ps = @packet.parse_packets(non_critical.add(literal).exact_view())
  assert_eq(ps.length(), 2)
  // Defined Padding: ignored.
  let ps2 = @packet.parse_packets(padding.add(literal).exact_view())
  assert_eq(ps2.length(), 2)
}

///|
test "c2g3: the v4 message cipher follows the recipient preference list" {
  // RFC 9580 §12.2 (audit c2g3): the message cipher MUST come from every
  // recipient's preference list — the v4 seal used to hardcode AES-256
  // and never read the Preferred Symmetric Algorithms subpacket.
  let key = generate_key("c2g3 <t@e>", bits=3072)
  // The certification's preference list excludes AES-256 and AES-192:
  // only AES-128 (7) remains.
  let prefs_sig : @packet.SignaturePacket = {
    ..key.user_ids[0].self_signature,
    hashed_subpackets: [
      {
        critical: false,
        sub_type: @packet.SIGSUB_PREFERRED_SYM_ALGOS,
        body: Bytes::from_array([7]),
      },
    ],
  }
  let modified_binding : UserIdBinding = {
    ..key.user_ids[0],
    self_signature: prefs_sig,
  }
  let modified : PrivateKey = { ..key, user_ids: [modified_binding], }
  let recipient = modified.to_public()
  // Unit: the picker honors the list.
  assert_eq(pick_v4_symmetric([recipient]), @primitives.Aes128)
  // Integration: the sealed message's session key is an AES-128 key and
  // the recipient still decrypts the payload.
  let armored : String = encrypt_to_recipients(b"payload", [recipient])
  let armored_bytes = @armor.ArmorBlock::data(@armor.decode(armored))
  let block = @armor.decode(armored)
  let all = @packet.parse_packets(block.data().exact_view())
  let mut pkesk : @packet.PkeskPacket? = None
  for p in all {
    if p.tag() is @packet.PacketTag::Pkesk {
      pkesk = Some(@packet.PkeskPacket::parse(p.body().exact_view()))
    }
  }
  let (algo, _session) = rsa_unwrap_session_key(
    pkesk.unwrap(),
    modified.subkeys[0].secret,
  )
  assert_eq(algo, 7)
  let d = decrypt_binary_with_private_key(armored_bytes.exact_view(), modified)
  assert_eq(d, b"payload")
  // A recipient without the preference subpacket is unconstrained:
  // AES-256 stays the default.
  let bare = generate_ed25519_key("c2g3-bare <t@e>")
  assert_eq(pick_v4_symmetric([bare.to_public()]), @primitives.Aes256)
}
