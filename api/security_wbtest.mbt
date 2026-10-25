///|
/// S-series fix regression tests (whitebox: they drive the private
/// signature-assembly helpers directly, so the hostile subpackets are
/// covered by a *cryptographically valid* signature — only the critical /
/// lifecycle rules can reject them, not a digest mismatch).

///|
/// A v4 document signature whose hashed area carries `extra`, fully
/// signed: the digest is computed over the injected subpackets too.
fn document_signature_with_extra(
  key : PrivateKey,
  data : BytesView,
  extra : Array[@packet.SigSubpacket],
  created : Int32,
) -> @packet.SignaturePacket raise {
  let hashed : Array[@packet.SigSubpacket] = [
    creation_subpacket(created),
    key_flags_subpacket(0x02),
    ..extra,
  ]
  let sig : @packet.SignaturePacket = {
    version: 4,
    sig_type: @packet.BinaryDocument,
    pub_algo: key.primary.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: key.primary.public.key_id(),
      },
    ],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: Bytes::new(0),
    sig_params: [],
  }
  let digest = document_hash(sig, data, @packet.BinaryDocument)
  finish_signature(sig, key.primary, @primitives.Sha256, digest.exact_view())
}

///|
/// The User ID self-certification of `key`, re-signed over `extra`
/// hashed subpackets (used to forge cryptographically valid certs that
/// carry hostile lifecycle or critical data).
fn recertify_with_extra(
  key : PrivateKey,
  extra : Array[@packet.SigSubpacket],
) -> @packet.SignaturePacket raise {
  let uid = key.user_id()
  let base = key.self_signature()
  let cert : @packet.SignaturePacket = {
    ..base,
    hashed_subpackets: [..base.hashed_subpackets(), ..extra],
    raw_hashed_area: Bytes::new(0),
  }
  let digest = hash_certification(cert, key.primary.public, uid)
  finish_signature(cert, key.primary, @primitives.Sha256, digest.exact_view())
}

///|
/// A signed primary-key revocation (type 0x20, valid at `now`).
fn signed_key_revocation(
  key : PrivateKey,
  now : Int32,
) -> @packet.SignaturePacket raise {
  let rev : @packet.SignaturePacket = {
    version: 4,
    sig_type: @packet.KeyRevocation,
    pub_algo: key.primary.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: [creation_subpacket(now)],
    unhashed_subpackets: [],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: Bytes::new(0),
    sig_params: [],
  }
  let digest = hash_direct_key(rev, key.primary.public)
  finish_signature(rev, key.primary, @primitives.Sha256, digest.exact_view())
}

///|
test "S01: an unknown critical subpacket fails document verification" {
  let key = generate_key("S1 <s1@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("signed body")
  let hostile : Array[@packet.SigSubpacket] = [
    {
      critical: true,
      sub_type: 100,
      // unassigned type, hence unknown to the recognized set
      body: @primitives.utf8_bytes("future mandatory semantics"),
    },
  ]
  let sig = document_signature_with_extra(
    key,
    data.exact_view(),
    hostile,
    1_700_000_000,
  )
  assert_eq(verify_signature_packet(sig, data, key.to_public()), Failed)
  // The very same unknown subpacket without the critical bit is ignored.
  let lenient : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: 100,
      body: @primitives.utf8_bytes("future optional semantics"),
    },
  ]
  let sig2 = document_signature_with_extra(
    key,
    data.exact_view(),
    lenient,
    1_700_000_000,
  )
  assert_eq(verify_signature_packet(sig2, data, key.to_public()), Ok)
}

///|
test "S01: a certification with an unknown critical subpacket does not verify" {
  let key = generate_key("S1b <s1b@example.com>", bits=2048)
  let forged = recertify_with_extra(key, [
    { critical: true, sub_type: 100, body: @primitives.utf8_bytes("x"), },
  ])
  assert_false(
    verify_key_signature(
      forged,
      key.primary.public,
      key.primary.public,
      user_id=key.user_id(),
    ),
  )
  // Sanity: re-certifying WITHOUT the hostile subpacket still verifies —
  // the rejection is the critical rule, not the re-signing.
  let clean = recertify_with_extra(key, [])
  assert_true(
    verify_key_signature(
      clean,
      key.primary.public,
      key.primary.public,
      user_id=key.user_id(),
    ),
  )
}

///|
test "S02: a signature from a self-revoked key reports KeyRevoked" {
  let key = generate_key("S2 <s2@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("body")
  let sig = document_signature_with_extra(
    key,
    data.exact_view(),
    [],
    1_700_000_000,
  )
  let now = @primitives.unix_now().to_int()
  let revoked_pk = {
    ..key.to_public(),
    revocations: [signed_key_revocation(key, now)],
  }
  assert_true(revoked_pk.is_revoked(@primitives.unix_now()))
  assert_eq(verify_signature_packet(sig, data, revoked_pk), KeyRevoked)
  // The same signature under the live key stays Ok.
  assert_eq(verify_signature_packet(sig, data, key.to_public()), Ok)
}

///|
test "S02: an expired signature reports Expired" {
  let key = generate_key("S2b <s2b@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("body")
  let created = 1_600_000_000 // 2020-09-13
  let sixty : Int32 = 60
  let expires : Array[@packet.SigSubpacket] = [
    {
      critical: false,
      sub_type: @packet.SIGSUB_SIG_EXPIRATION_TIME,
      body: Bytes::makei(4, i => (sixty >> (24 - i * 8)).to_byte()),
    },
  ]
  let sig = document_signature_with_extra(
    key,
    data.exact_view(),
    expires,
    created,
  )
  // Any clock past created+60 sees the signature expired. (On clock-less
  // targets unix_now() reads 0 and the check is skipped by design —
  // the native test runner always has a clock.)
  if @primitives.unix_now() > 1_600_000_060L {
    assert_eq(verify_signature_packet(sig, data, key.to_public()), Expired)
  }
}

///|
test "S02: a signature from an expired primary key reports Expired" {
  let key = generate_key("S2c <s2c@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("body")
  let sig = document_signature_with_extra(
    key,
    data.exact_view(),
    [],
    1_700_000_000,
  )
  // Re-certify the User ID with a Key Expiration Time 60 s after the
  // key's creation — long past on any real clock.
  let exp = key.primary.public.creation_time + 60
  let expired_cert = recertify_with_extra(key, [
    {
      critical: false,
      sub_type: @packet.SIGSUB_KEY_EXPIRATION_TIME,
      body: Bytes::makei(4, i => (exp >> (24 - i * 8)).to_byte()),
    },
  ])
  let expired_key : PublicKey = {
    ..key.to_public(),
    user_ids: [{ user_id: key.user_id(), self_signature: expired_cert, }],
  }
  if @primitives.unix_now() > exp.to_int64() {
    assert_true(expired_key.is_expired(@primitives.unix_now()))
    assert_eq(verify_signature_packet(sig, data, expired_key), Expired)
  }
}
