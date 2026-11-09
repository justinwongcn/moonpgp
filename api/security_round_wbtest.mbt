///|
/// Security-fix-round tests (2026-11): S1–S5 gates and C1–C5 correctness
/// fixes, each written as a before/after differential — the buggy behavior
/// is exactly what turns the assert red, and the honest-path behavior keeps
/// it green.

///|
test "add_user_id inherits the key-level expiry (S2)" {
  let key = generate_ed25519_key("AU <au@example.net>").set_expiry(3600)
  let now = @primitives.unix_now()
  if now != 0L {
    let later = now + 7200
    assert_true(key.is_expired(later))
    assert_eq(key.user_ids[0].self_signature.key_expiration_time(), 3600)
    // Re-certifying the first user id used to drop the Key Expiration
    // Time (S2): the certificate turned from expired to immortal, on
    // disk and for every verifying peer.
    let recert = key.add_user_id("AU <au@example.net>")
    assert_eq(recert.user_ids[0].self_signature.key_expiration_time(), 3600)
    assert_true(recert.is_expired(later))
    // The re-issued certification is wire-valid: re-import keeps the gate.
    let re = PrivateKey::from_bytes(recert.to_bytes().exact_view())
    assert_true(re.is_expired(later))
    // Appending a fresh user id (the first untouched) keeps it too.
    let append = key.add_user_id("AU2 <au2@example.net>")
    assert_true(append.is_expired(later))
  }
}

///|
test "s2k budget books saturated argon2 and clamps iterated overcharges (S3)" {
  let b = S2KBudget::new()
  assert_false(b.exhausted())
  // One saturated Argon2 specifier (t=255 over the 64 MiB cap) books 255.
  b.charge_argon2(255, 65536)
  assert_eq(b.charged, 255)
  // A gopenpgp-default derivation (t=3) books 3.
  b.charge_argon2(3, 65536)
  assert_eq(b.charged, 258)
  // Two more saturated attempts reach the budget line exactly.
  b.charge_argon2(255, 65536)
  b.charge_argon2(255, 65536)
  assert_true(b.exhausted())
  // A max-count iterated specifier books far more raw units than its
  // milliseconds of SHA-256 cost; the clamp keeps it at the Argon2 worst.
  b.charge_iterated(65011712)
  assert_eq(b.charged, 1023)
}

///|
test "a message packed with heavy SKESKs hits the per-message budget (S3)" {
  // Six v4 SKESKs, each with a max-cost iterated S2K (count byte 255 →
  // 65011712 hashed octets): the old retry loop paid all six on a wrong
  // passphrase — ~10 KB of message buying minutes of CPU. The budget
  // refuses attempt five with an explicit error.
  let skesk : @packet.SkeskPacket = {
    version: 4,
    cipher_algo: @primitives.Aes256.number(),
    aead_algo: 0,
    s2k: @s2k.Iterated(@primitives.Sha256, Bytes::make(8, 0x42), 255),
    iv: Bytes::new(0),
    encrypted_session_key: Bytes::make(48, 0x00),
  }
  let body = skesk.to_body()
  let w = @packet.Writer::new()
  for _ in 0..<6 {
    w.bytes(
      @packet.serialize_packet(@packet.Skesk, body.exact_view()).exact_view(),
    )
  }
  let armored = @armor.Message.encode(w.to_bytes().exact_view())
  let raised = try {
    let _ = decrypt_binary_with_password(
      @armor.ArmorBlock::data(@armor.decode(armored)).exact_view(),
      "definitely-wrong",
    )
    false
  } catch {
    e => {
      let msg = "\{e}"
      msg.contains("budget")
    }
  }
  assert_true(raised)
}

///|
test "an unparseable ESK does not abort the message (S4)" {
  let key = generate_ed25519_key("S4 <s4@example.net>")
  let msg = encrypt_to_recipients(b"hello", [key.to_public()])
  let data = @armor.ArmorBlock::data(@armor.decode(msg))
  let packets = @packet.parse_packets(data.exact_view())
  let w = @packet.Writer::new()
  // A PKESK whose version byte no parser accepts — RFC 9580 §10.3.2.1
  // says discard and continue, not fail the whole message.
  w.bytes(
    @packet.serialize_packet(
      @packet.Pkesk,
      Bytes::from_array([0x07, 0x00, 0x00]).exact_view(),
    ).exact_view(),
  )
  for p in packets {
    w.bytes(
      @packet.serialize_packet(p.tag(), p.body().exact_view()).exact_view(),
    )
  }
  let poisoned = @armor.Message.encode(w.to_bytes().exact_view())
  let plain = decrypt_with_private_key(poisoned, key)
  assert_eq(plain, @primitives.utf8_bytes("hello"))
}

///|
test "a v6 anonymous PKESK (size octet 0) decrypts (S5)" {
  let key = generate_ed25519_v6_key("S5 <s5@example.net>")
  let msg = encrypt_to_recipients(b"hello", [key.to_public()])
  let data = @armor.ArmorBlock::data(@armor.decode(msg))
  let packets = @packet.parse_packets(data.exact_view())
  let w = @packet.Writer::new()
  for p in packets {
    if p.tag() == @packet.Pkesk {
      // v6 PKESK body: [6, size, keyver, fp(32), algo, eph(32), len,
      // wrapped…]. The anonymous shape (§5.1.2/§5.1.8) drops keyver+fp:
      // [6, 0, algo, eph, len, wrapped…].
      guard p.body()[1].to_int() == 33 else {
        fail("unexpected v6 PKESK shape")
      }
      let anon = Bytes::from_array([p.body()[0], 0]).add(
        p.body()[35:].to_owned(),
      )
      w.bytes(
        @packet.serialize_packet(@packet.Pkesk, anon.exact_view()).exact_view(),
      )
    } else {
      w.bytes(
        @packet.serialize_packet(p.tag(), p.body().exact_view()).exact_view(),
      )
    }
  }
  let hidden = @armor.Message.encode(w.to_bytes().exact_view())
  // The library used to skip this legal shape entirely — the hidden
  // recipient could never decrypt.
  let plain = decrypt_with_private_key(hidden, key)
  assert_eq(plain, @primitives.utf8_bytes("hello"))
  // And a foreign key still unwraps nothing.
  let other = generate_ed25519_v6_key("O5 <o5@example.net>")
  let raised = try {
    let _ = decrypt_with_private_key(hidden, other)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "import refuses a mixed-generation certificate (C1)" {
  let v6 = generate_ed25519_v6_key("M6 <m6@example.net>")
  let v4 = generate_ed25519_key("M4 <m4@example.net>")
  // A v4 subkey bound by the v6 primary: the binding verifies
  // cryptographically, so only the generation guard can reject it. (The
  // builder-side guard refuses to CREATE such a binding; import re-checks
  // because certificates arrive from the outside world.) The base
  // signature's pub_algo must already name the v6 signer — the digest
  // covers it, and re-signing a legacy-labelled packet with native
  // Ed25519 material would produce a malformed signature.
  let sub = v4.subkeys[0].secret
  let base = { ..v4.subkeys[0].binding, pub_algo: v6.primary.public.algo(), }
  let forged_binding = reissue_sig(
    base,
    v6.primary,
    v4.subkeys[0].binding.hashed_subpackets,
    s => hash_binding(s, v6.primary.public, sub.public),
  )
  let mixed : PrivateKey = {
    ..v6,
    subkeys: [
      SecretSubkeyCert::{
        secret: sub,
        binding: forged_binding,
        revocation: None,
      },
    ],
  }
  let raised = try {
    let _ = PrivateKey::from_bytes(mixed.to_bytes().exact_view())
    false
  } catch {
    e => {
      let msg = "\{e}"
      msg.contains("does not match primary key version")
    }
  }
  assert_true(raised)
}

///|
test "a tampered v6 fast_hash fails key-signature verification (C2)" {
  let key = generate_ed25519_v6_key("F6 <f6@example.net>")
  let sig = key.user_ids[0].self_signature
  assert_true(
    verify_key_signature(
      sig,
      key.primary.public,
      key.primary.public,
      user_id=key.user_id(),
    ),
  )
  // RFC 9580 §5.2.4: the left 16 digest bits are a MUST-check for v6
  // verifiers — document verification had it, key signatures did not.
  let tampered = { ..sig, fast_hash: sig.fast_hash() ^ 1, }
  assert_false(
    verify_key_signature(
      tampered,
      key.primary.public,
      key.primary.public,
      user_id=key.user_id(),
    ),
  )
}

///|
test "verification refuses an uncrossed signing subkey (C3)" {
  let key = generate_ed25519_v6_key_with_signing_subkey("U6 <u6@example.net>")
  let data : Bytes = b"payload"
  let sig = sign_detached(data.exact_view(), key)
  // Control: the intact key verifies.
  assert_true(verify_detached(data.exact_view(), sig, key.to_public()) is Ok)
  // Strip the embedded Primary Key Binding in memory: the issuing side
  // refuses such a subkey outright; the verify side used to answer Ok
  // where gpg says Failed.
  let stripped : PrivateKey = {
    ..key,
    subkeys: key.subkeys.map(fn(c) {
      { ..c, binding: strip_embedded_signatures(c.binding), }
    }),
  }
  assert_true(
    verify_detached(data.exact_view(), sig, stripped.to_public()) is Failed,
  )
}

///|
test "an MD5 document signature fails verification (C5)" {
  let key = generate_ed25519_key("M5 <m5@example.net>")
  let data : Bytes = b"md5 payload"
  // A cryptographically REAL MD5 signature — before C5 it verified as Ok
  // and only gpg said no.
  let md5_sig = make_document_signature_with(
    key.primary,
    data.exact_view(),
    @packet.BinaryDocument,
    @primitives.Md5,
  )
  let armored_md5 = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, md5_sig.to_body().exact_view()).exact_view(),
  )
  assert_true(
    verify_detached(data.exact_view(), armored_md5, key.to_public()) is Failed,
  )
  // SHA-256 stays the honest path.
  let sha_sig = make_document_signature_with(
    key.primary,
    data.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha256,
  )
  let armored_sha = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sha_sig.to_body().exact_view()).exact_view(),
  )
  assert_true(
    verify_detached(data.exact_view(), armored_sha, key.to_public()) is Ok,
  )
  // The same refusal guards the key-signature entry point: a real MD5
  // certification must not re-validate.
  let base = key.user_ids[0].self_signature
  let fresh : @packet.SignaturePacket = {
    ..base,
    hash_algo: @primitives.Md5.number(),
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    sig_params: [],
  }
  let digest = hash_certification(fresh, key.primary.public, key.user_id())
  let md5cert = finish_signature(
    fresh,
    key.primary,
    @primitives.Md5,
    digest.exact_view(),
  )
  assert_false(
    verify_key_signature(
      md5cert,
      key.primary.public,
      key.primary.public,
      user_id=key.user_id(),
    ),
  )
}
