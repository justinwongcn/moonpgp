///|
/// Published GCM test cases (NIST SP 800-38D / McGrew-Viega GCM spec
/// test cases 1-4 and 15, the latter on AES-256): key, IV (12 octets),
/// associated data, plaintext, expected ciphertext and tag. TC16 needs
/// an 8-octet IV (GHASH-derived J0) which OpenPGP never uses, so it is
/// deliberately out of scope.

///|
fn check_gcm_case(
  key : String,
  iv : String,
  ad : String,
  plain : String,
  ct_hex : String,
  tag_hex : String,
) -> Unit raise {
  let kb = @primitives.from_hex(key)
  let algo = if kb.length() == 16 {
    @primitives.Aes128
  } else {
    @primitives.Aes256
  }
  let bc = @primitives.new_block_cipher(algo, kb.exact_view())
  let got = @cipher.gcm_encrypt(
    bc,
    @primitives.from_hex(iv).exact_view(),
    @primitives.from_hex(ad).exact_view(),
    @primitives.from_hex(plain).exact_view(),
  )
  assert_eq(@primitives.to_hex(got), ct_hex + tag_hex)
  // Decrypt round-trip, then a tampered tag must raise.
  let back = @cipher.gcm_decrypt(
    bc,
    @primitives.from_hex(iv).exact_view(),
    @primitives.from_hex(ad).exact_view(),
    got.exact_view(),
  )
  assert_eq(@primitives.to_hex(back), plain)
  let arr : Array[Byte] = []
  for i in 0..<got.length() {
    arr.push(got[i])
  }
  let last = got.length() - 1
  arr[last] = (arr[last].to_int() ^ 1).to_byte()
  let raised = try {
    let _ = @cipher.gcm_decrypt(
      bc,
      @primitives.from_hex(iv).exact_view(),
      @primitives.from_hex(ad).exact_view(),
      Bytes::from_array(arr).exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "gcm nist test cases" {
  // TC1: empty plaintext and AD.
  check_gcm_case(
    "00000000000000000000000000000000", "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a",
  )
  // TC2: one zero block, empty AD.
  check_gcm_case(
    "00000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000",
    "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf",
  )
  // TC3: 64-octet plaintext, empty AD (AES-128).
  check_gcm_case(
    "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
    "4d5c2af327cd64a62cf35abd2ba6fab4",
  )
  // TC4: 60-octet plaintext with a 20-octet AD.
  check_gcm_case(
    "feffe9928665731c6d6a8f9467308308",
    "cafebabefacedbaddecaf888",
    "feedfacedeadbeef" + "feedfacedeadbeefabaddad2",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    "5bc94fbc3221a5db94fae95ae7121a47",
  )
  // TC15: AES-256, 64-octet plaintext, empty AD.
  check_gcm_case(
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
    "", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
    "b094dac5d93471bdec1a502270e3cc6c",
  )
}

///|
test "gcm rejects a non-12-octet IV" {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes128,
    Bytes::make(16, b'\x00').exact_view(),
  )
  let raised = try {
    let _ = @cipher.gcm_encrypt(
      bc,
      Bytes::make(8, b'\x00').exact_view(),
      Bytes::new(0).exact_view(),
      Bytes::new(0).exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
