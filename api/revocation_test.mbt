///|
/// Task 2a: revocation certificate generation. Every lifecycle gate that
/// already CONSUMED revocations (is_revoked, can_encrypt, can_verify,
/// signature verification) must see a freshly revoked key as revoked, and
/// the revocation must survive export/import round trips. Cross-checked
/// against gpg 2.4.5 during development (both the embedded form and the
/// standalone `.rev` certificate import and mark the key revoked).

///|
test "revoke_key flips every lifecycle gate and round-trips" {
  let key = @api.generate_ed25519_key("Rev <rev@example.com>")
  let data = @primitives.utf8_bytes("signed before revocation")
  // A signature made BEFORE the revocation...
  let sig = @api.sign_detached(data, key)
  let revoked = @api.revoke_key(
    key,
    reason=@api.Compromised,
    message="laptop stolen",
  )
  let now = @primitives.unix_now()
  assert_true(revoked.to_public().is_revoked(now))
  assert_false(revoked.to_public().can_encrypt(now))
  assert_false(revoked.to_public().can_verify(now))
  // ...now verifies as KeyRevoked (cryptographically valid, key rejected).
  assert_eq(
    @api.verify_detached(data, sig, revoked.to_public()),
    @api.KeyRevoked,
  )
  // The revocation survives export/import (to_bytes writes it).
  let re = @api.PrivateKey::from_bytes(revoked.to_bytes().exact_view())
  assert_true(re.to_public().is_revoked(now))
  // Decrypting mail that arrived before the revocation keeps working
  // (decryption is deliberately not lifecycle-gated).
  let older = @api.encrypt_to_recipients(data, [key.to_public()])
  assert_eq(@api.decrypt_with_private_key(older, revoked), data)
}

///|
test "revoke_subkey drops the subkey from selection but not from decryption" {
  let key = @api.generate_ed25519_key("Sub <sub@example.com>")
  let sub_id = key.subkeys[0].secret.public.key_id()
  let older = @api.encrypt_to_recipients(
    @primitives.utf8_bytes("pre-revocation mail"),
    [key.to_public()],
  )
  let revoked = @api.revoke_subkey(key, sub_id, reason=@api.Retired)
  let now = @primitives.unix_now()
  // The Ed25519 primary cannot encrypt, so the key loses encryption
  // entirely once its only subkey is revoked.
  assert_false(revoked.to_public().can_encrypt(now))
  // Pre-revocation mail still decrypts with the revoked subkey.
  assert_eq(
    @api.decrypt_with_private_key(older, revoked),
    @primitives.utf8_bytes("pre-revocation mail"),
  )
  // Round trip keeps the subkey revocation.
  let re = @api.PrivateKey::from_bytes(revoked.to_bytes().exact_view())
  assert_true(re.subkeys[0].revocation is Some(_))
  assert_false(re.to_public().can_encrypt(now))
}

///|
test "revoke_subkey with an unknown key id fails loudly" {
  let key = @api.generate_key("Rsa <rsa@example.com>", bits=2048)
  // The primary's id is not a subkey id.
  let raised = try {
    let _ = @api.revoke_subkey(key, key.primary.public.key_id())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("no subkey"))
      true
    }
  }
  assert_true(raised)
}

///|
test "v6 key revocation round-trips" {
  let v6 = @api.generate_ed25519_v6_key("V6 Rev <v6rev@example.com>")
  let revoked = @api.revoke_key(v6, reason=@api.Superseded, message="v6 too")
  let now = @primitives.unix_now()
  assert_true(revoked.to_public().is_revoked(now))
  let re = @api.PrivateKey::from_bytes(revoked.to_bytes().exact_view())
  assert_true(re.to_public().is_revoked(now))
  assert_eq(re.revocations[0].version(), 6)
}

///|
test "standalone revocation certificate generates, applies, and rejects misuse" {
  let key = @api.generate_ed25519_key("Cert <cert@example.com>")
  let cert = @api.generate_revocation_certificate(
    key,
    reason=@api.Compromised,
    message="standalone",
  )
  // Applying to the matching public key revokes it.
  let pub_armored = key.to_public()
  let revoked = pub_armored.apply_revocation_certificate(cert)
  assert_true(revoked.is_revoked(@primitives.unix_now()))
  // A certificate for ANOTHER key must be rejected, not silently ignored.
  let other = @api.generate_ed25519_key("Other <other@example.com>")
  let raised = try {
    let _ = other.to_public().apply_revocation_certificate(cert)
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("does not verify"))
      true
    }
  }
  assert_true(raised)
  // A non-revocation signature in the same armor shape is rejected.
  let data = @primitives.utf8_bytes("not a revocation")
  let not_rev = @api.sign_detached(data, key)
  let raised2 = try {
    let _ = key.to_public().apply_revocation_certificate(not_rev)
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("not a key revocation"))
      true
    }
  }
  assert_true(raised2)
  // The private half accepts it too.
  let priv_revoked = key.apply_revocation_certificate(cert)
  assert_true(priv_revoked.to_public().is_revoked(@primitives.unix_now()))
}

///|
/// W2: v6 subkey revocation — the v6 branch of the subkey-revocation
/// signature (version 6, no Issuer Key ID, the primary named by
/// fingerprint in the hashed area). The revoked encryption subkey drops
/// out of selection immediately, mail that arrived earlier keeps
/// decrypting, and the revocation survives re-export.
test "revoke_subkey on a v6 key emits a v6 revocation and gates selection" {
  let key = @api.generate_ed25519_v6_key("V6 Sub Rev <v6sr@example.com>")
  let enc = key.subkeys[0]
  let sub_id = enc.secret.public.key_id()
  // Mail encrypted BEFORE the revocation...
  let data = @primitives.utf8_bytes("written before the subkey died")
  let msg = @api.encrypt_to_recipients(data, [key.to_public()])
  let revoked = @api.revoke_subkey(
    key,
    sub_id.exact_view(),
    reason=@api.Retired,
  )
  // The revocation signature is a v6 SubkeyRevocation signed by the
  // primary: no Issuer Key ID in the unhashed area, the primary named by
  // fingerprint in the hashed area.
  let r = revoked.subkeys[0].revocation
  guard r is Some(sig) else { abort("missing subkey revocation") }
  guard sig.sig_type() == @packet.SubkeyRevocation else {
    abort("wrong revocation type")
  }
  guard sig.version() == 6 else { abort("subkey revocation is not v6") }
  guard @packet.find_subpacket(
      sig.unhashed_subpackets,
      @packet.SIGSUB_ISSUER_KEY_ID,
    )
    is None else {
    abort("v6 revocation must not carry an Issuer Key ID")
  }
  let issuer_fp = @packet.find_subpacket(
    sig.hashed_subpackets,
    @packet.SIGSUB_ISSUER_FINGERPRINT,
  )
  guard issuer_fp is Some(fp) && fp.length() == 33 && fp[0].to_int() == 6 else {
    abort("v6 revocation lacks a v6 issuer fingerprint")
  }
  assert_eq(fp.exact_view()[1:].to_owned(), key.primary.public.fingerprint())
  guard @api.verify_key_signature(sig, key.primary.public, enc.secret.public) else {
    abort("v6 subkey revocation does not verify")
  }
  // The revoked subkey drops out of encryption selection immediately...
  guard !revoked.to_public().can_encrypt(@primitives.unix_now()) else {
    abort("revoked v6 encryption subkey still selectable")
  }
  // ...but mail that arrived earlier still decrypts.
  assert_eq(
    @utf8.decode_lossy(@api.decrypt_with_private_key(msg, revoked).exact_view()),
    "written before the subkey died",
  )
  // And the revocation survives re-export.
  let back = @api.PrivateKey::from_armored(revoked.to_armored())
  guard back.subkeys[0].revocation is Some(_) else {
    abort("round-trip lost the subkey revocation")
  }
}
