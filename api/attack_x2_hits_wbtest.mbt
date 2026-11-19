///|
/// X2 HIT regressions (audit-conformance-20261119) — each probe began life
/// as an attack-round RED assertion of the lenient behavior and has been
/// flipped to the strict outcome after the fix:
/// - P5d: OPS inside compression now pairs with the signature outside it
///   (hit-2 fix: the OPS state threads through compressed layers) — the
///   hash-mismatched signature is ignored → NotSigned.
/// - P5e: an unparseable OPS voids the stream's signatures (hit-2 fix:
///   broken flag) → NotSigned.
/// - P7a/P7f: SHA-1 / RIPEMD-160 signature with no creation-time subpacket
///   fails the §9.5 recent gate (hit-3 fix: "not recent" is unprovable) →
///   Failed.
/// - P6g: the c2g5 parse-level checksum gate lives in the usage-0 branch
///   only; a legitimately locked usage-254 key (ciphertext, check riding
///   inside the encryption) still parses and round-trips.

///|
/// P5d (c1g6/hit-2 regression): the OPS lives inside a Compressed packet
/// but the trailing signature sits OUTSIDE it. The threaded OPS state
/// pairs the two; the signature is SHA-512 against a SHA-256 OPS, so
/// RFC 9580 §5.2.5 ignores it for validation → NotSigned.
test "x2 P5d: OPS inside compression pairs with the outer signature" {
  let key = generate_ed25519_key("S <s@example.com>")
  let signer = key.primary
  let sig = make_document_signature_with(
    signer,
    x2_payload.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha512,
  )
  let ops = one_pass_sig_for(signer, sig, @primitives.Sha256)
  // Algo-0 Compressed packet whose inner sequence is [OPS || Literal].
  let inner = Bytes::from_array([0])
    .add(
      @packet.serialize_packet(@packet.OnePassSig, ops.to_body().exact_view()),
    )
    .add(
      @packet.serialize_packet(
        @packet.Literal,
        @packet.LiteralPacket::binary(
          x2_payload.exact_view(),
          file_name="x.txt",
        )
        .to_body()
        .exact_view(),
      ),
    )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.Compressed, inner.exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  let (data, status) = verify_inline(
    @armor.Message.encode(w.to_bytes().exact_view()),
    key.to_public(),
  )
  assert_eq(data, x2_payload)
  assert_eq(status, VerifyStatus::NotSigned)
}

///|
/// P5e (hit-2 regression): an unparseable OPS voids the stream — the
/// trailing signature must not validate against a pairing check that
/// silently disappeared.
test "x2 P5e: malformed OPS voids the trailing signature" {
  let key = generate_ed25519_key("S <s@example.com>")
  let signer = key.primary
  let sig = make_document_signature_with(
    signer,
    x2_payload.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha512,
  )
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.OnePassSig,
      Bytes::from_array([3, 0, 8]).exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(x2_payload.exact_view(), file_name="x.txt")
      .to_body()
      .exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  let (data, status) = verify_inline(
    @armor.Message.encode(w.to_bytes().exact_view()),
    key.to_public(),
  )
  assert_eq(data, x2_payload)
  assert_eq(status, VerifyStatus::NotSigned)
}

///|
/// P6g (c2g5 gate placement regression): the parse-level checksum gate
/// guards the usage-0 branch (plaintext material, RFC 9580 §5.5.3), not
/// the encrypted usages — a legitimately locked usage-254 key's wire
/// material is ciphertext whose check octets ride inside the encryption
/// and are verified after decryption at unlock time.
test "x2 P6g: locked key (usage 254) survives parse roundtrip" {
  let key = generate_ed25519_key("P <p@example.com>")
  let locked = lock_secret_key(key.primary, "passphrase-1")
  let wire = locked.to_body()
  let parsed : @packet.SecretKeyPacket = @packet.SecretKeyPacket::parse(
    wire.exact_view(),
  ) catch {
    _ => @error.fail("parse rejected a legitimately locked usage-254 key")
  }
  assert_eq(parsed.s2k_usage, 254)
  // Unlock the parsed-back key: the encrypted check rides inside the
  // ciphertext and must verify after decryption only.
  let unlocked = unlock_secret_key(
    parsed,
    "passphrase-1",
    0,
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
  )
  assert_eq(unlocked.s2k_usage, 0)
}

///|
/// P7a (hit-3 regression): a SHA-1 signature whose hashed area carries NO
/// creation-time subpacket cannot prove it predates the §9.5 cutoff, so it
/// verifies as Failed (RFC 9580 §5.2.3.4 makes the subpacket mandatory).
test "x2 P7a: SHA-1 sig without creation time is rejected" {
  let (key, armored) = x2_weak_sig_armored(@primitives.Sha1, [])
  let status = verify_detached(
    x2_payload.exact_view(),
    armored,
    key.to_public(),
  )
  assert_eq(status, VerifyStatus::Failed)
}

///|
/// P7f (hit-3 regression twin): RIPEMD-160 without a creation time —
/// same gate as P7a on the second §9.5 weak hash.
test "x2 P7f: RIPEMD-160 sig without creation time is rejected" {
  let (key, armored) = x2_weak_sig_armored(@primitives.Ripemd160, [])
  let status = verify_detached(
    x2_payload.exact_view(),
    armored,
    key.to_public(),
  )
  assert_eq(status, VerifyStatus::Failed)
}
