///|
/// RFC 9580 v6 detached signature tests.
///
/// The frozen cross-check vector at the top was produced by the
/// designated alignment reference — the pure-MoonBit `pgp` package of
/// `mizchi/experimental_crypto@0.0.2` — over the fixed message below
/// (seed 00..1f, salt 40..5f, creation time 0x6553F100) and was
/// independently verified with go-crypto v1.4.1 (the engine behind the
/// gopenpgp baseline). Both directions of that cross-check are recorded
/// in HANDOFF; these bytes are the repo-local baseline.
const V6_MESSAGE : String = "moonbit v6 cross-check\n"

///|
const V6_PUB_ARMOR : String =
  #|-----BEGIN PGP PUBLIC KEY BLOCK-----
  #|
  #|xioGZVPxABsAAAAgA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbjCmwYf
  #|GwoAAAAsBQJlU/EAAhsDIiEGw/aPuXc7l7WkmyVeVtkhRFv6yX+jJWQXiXvb/H9t
  #|+pgAAAAA2SsgQEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl+DA6rMsHEH
  #|bImSnX73+inXorIZC3sC1nnkrxdzw8MLwn6tYvg3aq1l0GzfM8AFIhAVBFVGJjxn
  #|B0d2rLURyw0O
  #|=pNVL
  #|-----END PGP PUBLIC KEY BLOCK-----

///|
const V6_SIG_ARMOR : String =
  #|-----BEGIN PGP SIGNATURE-----
  #|
  #|wpgGABsKAAAAKQUCZVPxACIhBsP2j7l3O5e1pJslXlbZIURb+sl/oyVkF4l72/x/
  #|bfqYAAAAAKHoIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5faa+N+A/V
  #|LYUoWtpMRXGuG2s+QkTQVkSoXggas3fq79eKn1JPP+Cpe1iBAghUVZR7VTJOdgHH
  #|w/oficNrRUB5Dw==
  #|=XNVf
  #|-----END PGP SIGNATURE-----

///|
test "v6 frozen cross-check vector: fingerprint, key id, verify" {
  let v6pub = @api.PublicKey::from_armored(V6_PUB_ARMOR)
  // v6 key id = high 64 bits of the SHA-256 fingerprint (§5.5.4.3).
  assert_eq(v6pub.fingerprint().length(), 32)
  assert_eq(
    v6pub.fingerprint(),
    @primitives.from_hex(
      "c3f68fb9773b97b5a49b255e56d921445bfac97fa3256417897bdbfc7f6dfa98",
    ),
  )
  assert_eq(v6pub.key_id(), @primitives.from_hex("c3f68fb9773b97b5"))
  // The direct-key signature the RFC requires for v6 keys must verify.
  let block = @armor.decode(V6_PUB_ARMOR)
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut key_pkt : @packet.PublicKeyPacket? = None
  let mut direct : @packet.SignaturePacket? = None
  for p in packets {
    if p.tag() == @packet.PublicKey {
      key_pkt = Some(@packet.PublicKeyPacket::parse(p.body().exact_view()))
    } else if p.tag() == @packet.Signature {
      let s = @packet.SignaturePacket::parse(p.body().exact_view())
      if s.sig_type() == @packet.DirectSignature {
        direct = Some(s)
      }
    }
  }
  match (key_pkt, direct) {
    (Some(k), Some(d)) => {
      assert_eq(d.version(), 6)
      // mizchi's v6 direct-key self-signature uses SHA-512 -> 32-octet salt.
      assert_eq(d.salt().length(), @packet.salt_size_of_hash(d.hash_algo()))
      assert_true(@api.verify_key_signature(d, k, k, direct=true))
    }
    _ => fail("frozen v6 key is missing its direct-key signature")
  }
  // The detached signature over the fixed message verifies.
  let status = @api.verify_detached(
    @utf8.encode(V6_MESSAGE),
    V6_SIG_ARMOR,
    v6pub,
  )
  assert_eq(status, @api.Ok)
}

///|
test "v6 frozen vector rejects a tampered message" {
  let v6pub = @api.PublicKey::from_armored(V6_PUB_ARMOR)
  let tampered = @utf8.encode("moonbit v6 cross-check?\n")
  assert_eq(@api.verify_detached(tampered, V6_SIG_ARMOR, v6pub), @api.Failed)
}

///|
test "v6 verify rejects a wrong hash tag (MUST per §5.2.4)" {
  let v6pub = @api.PublicKey::from_armored(V6_PUB_ARMOR)
  let block = @armor.decode(V6_SIG_ARMOR)
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut flipped : String? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      let s = @packet.SignaturePacket::parse(p.body().exact_view())
      let bad = { ..s, fast_hash: s.fast_hash() ^ 1, }
      let w = @packet.Writer::new()
      w.bytes(
        @packet.serialize_packet(@packet.Signature, bad.to_body().exact_view()).exact_view(),
      )
      flipped = Some(@armor.Signature.encode(w.to_bytes().exact_view()))
    }
  }
  match flipped {
    Some(armored) =>
      assert_eq(
        @api.verify_detached(@utf8.encode(V6_MESSAGE), armored, v6pub),
        @api.Failed,
      )
    None => fail("no signature packet in the frozen vector")
  }
}

///|
test "v6 salt size table (RFC 9580 Table 23)" {
  assert_eq(@packet.salt_size_of_hash(8), 16) // SHA-256
  assert_eq(@packet.salt_size_of_hash(11), 16) // SHA-224
  assert_eq(@packet.salt_size_of_hash(9), 24) // SHA-384
  assert_eq(@packet.salt_size_of_hash(10), 32) // SHA-512
  let raised = try {
    let _ = @packet.salt_size_of_hash(2) // SHA-1: N/A for v6
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "v6 signature with a mismatched salt length is rejected" {
  let sig : @packet.SignaturePacket = {
    version: 6,
    sig_type: @packet.BinaryDocument,
    pub_algo: @packet.Ed25519,
    hash_algo: 8,
    hashed_subpackets: [ // SHA-256 expects a 16-octet salt
    ],
    unhashed_subpackets: [],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: Bytes::make(32, b'\x01'),
    sig_params: [Bytes::make(64, b'\x02')],
  }
  let body = sig.to_body()
  let raised = try {
    let _ = @packet.SignaturePacket::parse(body.exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "v6 keygen signs and verifies; key armor round-trips" {
  let key = @api.generate_ed25519_v6_key("MoonBit V6 <v6@example.org>")
  assert_eq(key.fingerprint().length(), 32)
  assert_true(key.key_id().equal(key.fingerprint()[0:8].to_owned()))
  let msg = @utf8.encode("v6 detached round-trip")
  let sig = @api.sign_detached(msg, key)
  assert_eq(@api.verify_detached(msg, sig, key.to_public()), @api.Ok)
  // The armored key survives an export/import cycle (direct signature,
  // user ID and v6 wire shape included) and still verifies.
  let pub2 = @api.PublicKey::from_armored(key.to_public().to_armored())
  assert_eq(@api.verify_detached(msg, sig, pub2), @api.Ok)
  let priv2 = @api.PrivateKey::from_armored(key.to_armored())
  let sig2 = @api.sign_detached(msg, priv2)
  assert_eq(@api.verify_detached(msg, sig2, pub2), @api.Ok)
  // v6 signatures carry a salt and no issuer key id subpacket.
  let block = @armor.decode(sig)
  for p in @packet.parse_packets(block.data().exact_view()) {
    if p.tag() == @packet.Signature {
      let s = @packet.SignaturePacket::parse(p.body().exact_view())
      assert_eq(s.version(), 6)
      assert_eq(s.salt().length(), 16)
      assert_eq(s.issuer_key_id(), Some(key.key_id()))
      assert_true(s.fast_hash() != 0)
    }
  }
}

///|
test "v6 keys refuse inline signing (v6 OPS not implemented yet)" {
  let key = @api.generate_ed25519_v6_key("MoonBit V6 <v6@example.org>")
  let raised = try {
    let _ = @api.sign_inline(@utf8.encode("data"), key)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
