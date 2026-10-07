///|
/// RFC 7253 Appendix A vectors for OCB-AES-128 with TAGLEN=128:
/// K = 000102030405060708090A0B0C0D0E0F, N increments over the samples.
/// These 13 (N, A, P, C) tuples are the independent check for the mode
/// (verified first against the RFC's own internal values — bottom=15,
/// Ktop, Stretch, Offset_0).
const OCB_KEY_HEX : String = "000102030405060708090a0b0c0d0e0f"

///|
fn check_ocb_vector(
  n : String,
  a : String,
  p : String,
  c : String,
) -> Unit raise {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes128,
    @primitives.from_hex(OCB_KEY_HEX).exact_view(),
  )
  let nonce = @primitives.from_hex(n)
  let ad = @primitives.from_hex(a)
  let plain = @primitives.from_hex(p)
  let got = @cipher.ocb_encrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    plain.exact_view(),
  )
  assert_eq(@primitives.to_hex(got), c)
  let back = @cipher.ocb_decrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    got.exact_view(),
  )
  assert_eq(@primitives.to_hex(back), p)
}

///|
test "ocb rfc7253 appendix A vectors" {
  check_ocb_vector(
    "bbaa99887766554433221100", "", "", "785407bfffc8ad9edcc5520ac9111ee6",
  )
  check_ocb_vector(
    "bbaa99887766554433221101", "0001020304050607", "0001020304050607", "6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009",
  )
  check_ocb_vector(
    "bbaa99887766554433221102", "0001020304050607", "", "81017f8203f081277152fade694a0a00",
  )
  check_ocb_vector(
    "bbaa99887766554433221103", "", "0001020304050607", "45dd69f8f5aae72414054cd1f35d82760b2cd00d2f99bfa9",
  )
  check_ocb_vector(
    "bbaa99887766554433221104", "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f",
    "571d535b60b277188be5147170a9a22c3ad7a4ff3835b8c5701c1ccec8fc3358",
  )
  check_ocb_vector(
    "bbaa99887766554433221105", "000102030405060708090a0b0c0d0e0f", "", "8cf761b6902ef764462ad86498ca6b97",
  )
  check_ocb_vector(
    "bbaa99887766554433221106", "", "000102030405060708090a0b0c0d0e0f", "5ce88ec2e0692706a915c00aeb8b2396f40e1c743f52436bdf06d8fa1eca343d",
  )
  check_ocb_vector(
    "bbaa99887766554433221107", "000102030405060708090a0b0c0d0e0f1011121314151617",
    "000102030405060708090a0b0c0d0e0f1011121314151617", "1ca2207308c87c010756104d8840ce1952f09673a448a122c92c62241051f57356d7f3c90bb0e07f",
  )
  check_ocb_vector(
    "bbaa99887766554433221108", "000102030405060708090a0b0c0d0e0f1011121314151617",
    "", "6dc225a071fc1b9f7c69f93b0f1e10de",
  )
  check_ocb_vector(
    "bbaa99887766554433221109", "", "000102030405060708090a0b0c0d0e0f1011121314151617",
    "221bd0de7fa6fe993eccd769460a0af2d6cded0c395b1c3ce725f32494b9f914d85c0b1eb38357ff",
  )
  check_ocb_vector(
    "bbaa9988776655443322110a", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "bd6f6c496201c69296c11efd138a467abd3c707924b964deaffc40319af5a48540fbba186c5553c68ad9f592a79a4240",
  )
  check_ocb_vector(
    "bbaa9988776655443322110d", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
    "d5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7aed07ba06a4a69483a7035490c5769e60",
  )
  check_ocb_vector(
    "bbaa9988776655443322110f", "", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
    "4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e479ad363ac366b95a98ca5f3000b1479",
  )
}

///|
test "ocb rejects a tampered tag or ciphertext" {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes128,
    @primitives.from_hex(OCB_KEY_HEX).exact_view(),
  )
  let nonce = @primitives.from_hex("bbaa99887766554433221104")
  let ad = @primitives.from_hex("000102030405060708090a0b0c0d0e0f")
  let plain = @primitives.from_hex("000102030405060708090a0b0c0d0e0f")
  let ct = @cipher.ocb_encrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    plain.exact_view(),
  )
  // Flip one tag bit and one ciphertext bit: both must be rejected.
  let tag_arr : Array[Byte] = []
  for i in 0..<ct.length() {
    tag_arr.push(ct[i])
  }
  let last = ct.length() - 1
  tag_arr[last] = (tag_arr[last].to_int() ^ 1).to_byte()
  let bad_tag = Bytes::from_array(tag_arr)
  let raised_tag = try {
    let _ = @cipher.ocb_decrypt(
      bc,
      nonce.exact_view(),
      ad.exact_view(),
      bad_tag.exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised_tag)
  let ct_arr : Array[Byte] = []
  for i in 0..<ct.length() {
    ct_arr.push(ct[i])
  }
  ct_arr[0] = (ct_arr[0].to_int() ^ 1).to_byte()
  let bad_ct = Bytes::from_array(ct_arr)
  let raised_ct = try {
    let _ = @cipher.ocb_decrypt(
      bc,
      nonce.exact_view(),
      ad.exact_view(),
      bad_ct.exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised_ct)
}

///|
test "ocb rejects a bad nonce length" {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes128,
    @primitives.from_hex(OCB_KEY_HEX).exact_view(),
  )
  let raised = try {
    let _ = @cipher.ocb_encrypt(
      bc,
      Bytes::make(16, b'\x00').exact_view(),
      Bytes::new(0).exact_view(),
      Bytes::new(0).exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
