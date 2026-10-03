///|
/// OpenSSL 3.x cross-check key (2048-bit, e=65537) and vectors, generated
/// with `openssl genrsa`, `openssl dgst -sha256 -sign` over "abc", and
/// `openssl rsautl -pkcs -encrypt` over "test secret".
const TEST_N : String =
  #|bb60b4d02f2c2cba485cf72a438b9a86e47445ec8cb96e9a9251f6d233a30841df231e9edaadbbff959905dfdee38edc5c79974357a53ff389ba6d54930b81a74d99e269b4cfab3caf667de4fcddaab8930d6086369482b2bb3e260131eef222fd771cafc4ed8a30207029b814a059c4351994e0e516cd1748f4a553cd7e46fe77aaeedb0cfd222da762e4a49cda11413d3e4fb4df99a07b350a83d6487d20116c09d253c76114a16703a24e6ad60017fa2558ac6c268d84784602905be590453bc83cd277ec6b28b75d412baaf24a003670c816a968740e44f975874e3473f2e5ed72df0bf34e48276347b51e85e03f405ce04a5ccf41b17497a7b0697e1c1f

///|
const TEST_D : String =
  #|5c0ec906b70656fb366e2628a782c0eaa0f6d71bbe8fa3dd6121cfc7ba02d11dbbc8ff54404fb6db7cddef5aeba09521827562717d6ffc996403298fb1a6a78e50bbd7d6e3345c06b68dfe3030639f6a8b24b955771f438f181b1284e7c96340f992398fc98a82a7de67fcb729bb161f258f69eb8be1c5e538bca93520f27761d88cd26e636640adff4b5c8daf9afdf7824f00d76e62c7b801988f57312be2bc774ae84278c24be53ded2f1ec0f98a16f41a0ea75f027587d8c192623f7b16df20f3785df6f50b0d71d902254a326bce91c85ef094b40a777eaa3a9023f45270bdd7f12e7b9b47c8ba05710ebbc1ebeca4ffb757a77d6adc889bcec845a69671

///|
const TEST_P : String =
  #|fbe07cc1c1723ba6fee60ba04b4d217bf94720081fae642aab6b32fa0620ec7496f5d683b646b530c7890d15f3cd3a455a2322e67c9020b0c2265afe88767f341fac31211c48c6c74579781d790be71fef52921db42fcb4de84bacce4c438a4cde5a688d9800785ad8afdba67da01a1d828d5e23cd2b800d21cba3f4f4acf403

///|
const TEST_Q : String =
  #|be71edf674bd11c6c1fbaa0d143e93ae2c960cd0a5505652c9006b66f2f05fa01fad700ef72950abc742e31b6d89e6b821a57b54d4968839190949b01e9b24a3d5d9fadb84bca3ad560adf1fdff202a1b54f05e4f4ddd5f6a00e6067baf7f024d3a672b1659f841cf751f7ed221bdb9c4189612cfa8db6c80efd60c59d2f32b5

///|
const TEST_SIG : String =
  #|73a5f884a3d6beccb2140da110322d6eb38340757d314d05c48b2744bf36dc18569af90dfe26f17401b6fd276dde22e279a6790b34f20c57b04ff6526ec2d497bd51d87a7ef86ee408cae18733ba351ac9f21f2f158ebf5f1458d361084bf2eea51d7c270cdcea0b85439270daff1f3712f285b67c10deef4c97ecb1532f2c4f4790686dfa01c43145977e12643e2e08e15e562b7b6f5285343c5d14d253c77b92992ee2afb29a7e7e9032b4700ec2654be6916fd6141fbefa5ffec6f3f52bb1f629226825116fac1c390ba2725fa41f3d83b1413d0d5095324977c0b3cc0db525843d435c1861ba7da939143f5851d45435a808b219aa3f36fbb4b622f5fee6

///|
const TEST_CT : String =
  #|121ce66f49630a43f4cc3bfe65b9b8680ef545a858e6dd80f22010951fb7341a2cc570b1bd43b6234e2a2f57e586f8ccb23860e2a36dfdaa931fc593166e3fecee566d0912207e79a58f4629da6e4f3a090707b2547504b6375310fb1292582131ee7ec49cc8898fe3060418207073780a1992bd6ff8d7047f5155f8b75b64b1ebf1c68cdc63ecce033bd44ef0405ce1806dfcaf7e4d7002d9be42eb237fca8e7fb3685bf2e63a11785ef6587b488a442d97a7af05af4cd71140b9c7ef1bb7efd20658cac956690a8c3aa1cec7c9b2fbf4776bbb42b8d49a0bb5193ba33fc93e2e7d85a5788c5b4ff1dfbdaf6cacd0782233f695faf1e0a1ad296a8127708505

///|
fn test_private_key() -> @pki.RsaPrivateKey raise {
  let n = BigInt::from_string(TEST_N, radix=16)
  let e = BigInt::from_string("10001", radix=16)
  let d = BigInt::from_string(TEST_D, radix=16)
  let p = BigInt::from_string(TEST_P, radix=16)
  let q = BigInt::from_string(TEST_Q, radix=16)
  let u = @pki.mod_inverse(p, q)
  @pki.RsaPrivateKey::{ public: { n, e, }, d, p, q, u, }
}

///|
test "mod inverse" {
  // 17^-1 mod 3120 = 2753 (classic RSA textbook example)
  let inv = @pki.mod_inverse(BigInt::from_int(17), BigInt::from_int(3120))
  assert_eq(inv.to_string(), "2753")
}

///|
test "primality test" {
  assert_true(@pki.is_probable_prime(BigInt::from_int(2), rounds=20))
  assert_true(@pki.is_probable_prime(BigInt::from_int(97), rounds=20))
  // Carmichael number 561 = 3 * 11 * 17 must be composite.
  assert_false(@pki.is_probable_prime(BigInt::from_int(561), rounds=20))
  // 2^61 - 1 is a Mersenne prime.
  let m61 = BigInt::from_int(1).shl(61).sub(BigInt::from_int(1))
  assert_true(@pki.is_probable_prime(m61, rounds=20))
  // 2^61 + 1 = 3 * 768614336404564651 is composite.
  let m61p = BigInt::from_int(1).shl(61).add(BigInt::from_int(1))
  assert_false(@pki.is_probable_prime(m61p, rounds=20))
}

///|
test "openssl RSA signature reproduces exactly" {
  let key = test_private_key()
  let digest = @primitives.Sha256.digest(
    @primitives.utf8_bytes("abc").exact_view(),
  )
  let sig = key.pkcs1_v15_sign(@primitives.Sha256, digest.exact_view())
  assert_eq(@primitives.to_hex(sig), TEST_SIG)
  // And the public half verifies both ours and openssl's bytes.
  let ok = key.public.pkcs1_v15_verify(
    @primitives.Sha256,
    digest.exact_view(),
    sig.exact_view(),
  )
  assert_true(ok)
  let ok2 = key.public.pkcs1_v15_verify(
    @primitives.Sha256,
    digest.exact_view(),
    @primitives.from_hex(TEST_SIG).exact_view(),
  )
  assert_true(ok2)
}

///|
test "openssl RSA encryption decrypts" {
  let key = test_private_key()
  let ct = @primitives.from_hex(TEST_CT)
  let pt = key.pkcs1_v15_decrypt(ct.exact_view())
  assert_eq(pt, @primitives.utf8_bytes("test secret"))
}

///|
test "verify rejects tampered signature" {
  let key = test_private_key()
  let digest = @primitives.Sha256.digest(
    @primitives.utf8_bytes("abc").exact_view(),
  )
  let sig = @primitives.from_hex(TEST_SIG)
  // Flip last octet.
  let bad = sig[0:sig.length() - 1]
    .to_owned()
    .add(Bytes::from_array([sig[sig.length() - 1] ^ b'\x01']))
  assert_false(
    key.public.pkcs1_v15_verify(
      @primitives.Sha256,
      digest.exact_view(),
      bad.exact_view(),
    ),
  )
  // A SHA-1 digest under SHA-256 framing must not verify (returns false,
  // no raise).
  let digest_other = @primitives.Sha1.digest(
    @primitives.utf8_bytes("abc").exact_view(),
  )
  let raised = try {
    let _ = key.public.pkcs1_v15_verify(
      @primitives.Sha256,
      digest_other.exact_view(),
      sig.exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "generated key roundtrip (1024-bit)" {
  let key = @pki.generate_rsa_key(bits=1024)
  let msg = @primitives.utf8_bytes("roundtrip message for our own key")
  let ct = key.public.pkcs1_v15_encrypt(msg.exact_view())
  assert_eq(ct.length(), 128)
  let pt = key.pkcs1_v15_decrypt(ct.exact_view())
  assert_eq(pt, msg)
  let digest = @primitives.Sha256.digest(msg.exact_view())
  let sig = key.pkcs1_v15_sign(@primitives.Sha256, digest.exact_view())
  assert_true(
    key.public.pkcs1_v15_verify(
      @primitives.Sha256,
      digest.exact_view(),
      sig.exact_view(),
    ),
  )
}
