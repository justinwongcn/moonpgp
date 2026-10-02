///|
/// RFC 8032 §7.1 Ed25519 test vectors, run through the public API.
/// These pins the curve constants (d, L, base point), the seed expansion,
/// the deterministic nonce, and the verification equation in one sweep.

///|
test "RFC 8032 ed25519 test 1 (empty message)" {
  let key = @pki.ed25519_public_of_seed(
    @primitives.from_hex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ).view(),
  )
  assert_eq(
    @primitives.to_hex(key.public.view()),
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let sig = key.sign(Bytes::new(0).view())
  assert_eq(
    @primitives.to_hex(sig.view()),
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  let pk = @pki.ed25519_public_key(key.public.view())
  assert_true(pk.verify(Bytes::new(0).view(), sig.view()))
}

///|
test "RFC 8032 ed25519 test 2 (single byte)" {
  let key = @pki.ed25519_public_of_seed(
    @primitives.from_hex(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    ).view(),
  )
  assert_eq(
    @primitives.to_hex(key.public.view()),
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  )
  let msg = @primitives.from_hex("72")
  let sig = key.sign(msg.view())
  assert_eq(
    @primitives.to_hex(sig.view()),
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
  let pk = @pki.ed25519_public_key(key.public.view())
  assert_true(pk.verify(msg.view(), sig.view()))
  let tampered = @primitives.from_hex("73")
  assert_false(pk.verify(tampered.view(), sig.view()))
}

///|
test "RFC 8032 ed25519 test 3 (two bytes)" {
  let key = @pki.ed25519_public_of_seed(
    @primitives.from_hex(
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    ).view(),
  )
  assert_eq(
    @primitives.to_hex(key.public.view()),
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
  )
  let msg = @primitives.from_hex("af82")
  let sig = key.sign(msg.view())
  assert_eq(
    @primitives.to_hex(sig.view()),
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  )
  let pk = @pki.ed25519_public_key(key.public.view())
  assert_true(pk.verify(msg.view(), sig.view()))
}

///|
test "RFC 8032 ed25519 SHA(abc) vector" {
  let key = @pki.ed25519_public_of_seed(
    @primitives.from_hex(
      "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    ).view(),
  )
  assert_eq(
    @primitives.to_hex(key.public.view()),
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
  )
  let msg = @primitives.from_hex("616263")
  let sig = key.sign(msg.view())
  // Cross-checked byte-for-byte against `openssl pkeyutl -sign -rawin`
  // with the same seed imported via PKCS#8.
  assert_eq(
    @primitives.to_hex(sig.view()),
    "c9446c82f4235087613364b1e2c31aed0ae9f11a6982859914bdd8565e119d26" +
    "cd47423c26c2a49d5f60d847f75120f4bada1a01063aafef8fecb9a07e32e707",
  )
  let pk = @pki.ed25519_public_key(key.public.view())
  assert_true(pk.verify(msg.view(), sig.view()))
}

///|
test "ed25519 verify rejects malformed and malleable signatures" {
  let key = @pki.ed25519_public_of_seed(
    @primitives.from_hex(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    ).view(),
  )
  let pk = @pki.ed25519_public_key(key.public.view())
  let msg = @primitives.from_hex("72")
  let sig = key.sign(msg.view())
  // Truncated signature.
  assert_false(pk.verify(msg.view(), sig[0:63].view()))
  // Flipped bit in R.
  let r_arr : Array[Byte] = []
  for b in sig[0:32] {
    r_arr.push(b)
  }
  r_arr[0] = (r_arr[0].to_int() ^ 1).to_byte()
  let bad_r = Bytes::from_array(r_arr)
  assert_false(pk.verify(msg.view(), bad_r.add(sig[32:64].to_owned()).view()))
  // S >= L (malleable): all-ones S half.
  let big_s = Bytes::from_array([
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
  ])
  assert_false(pk.verify(msg.view(), sig[0:32].to_owned().add(big_s).view()))
  // Garbage public key decodes to false, not an error.
  let bad_pk = @pki.ed25519_public_key(
    @primitives.from_hex(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ).view(),
  )
  assert_false(bad_pk.verify(msg.view(), sig.view()))
}

///|
test "x25519 rejects low-order peer point" {
  let key = @pki.x25519_generate()
  let zero_u = Bytes::make(32, 0)
  let result = try? @pki.x25519_shared_secret(key.scalar.view(), zero_u.view())
  assert_true(result is Err(_))
}
