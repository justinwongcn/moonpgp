///|
/// M4 tests: compression on the encryption side and the decompressed-
/// payload ceiling.

///|
test "compressed output round-trips through our own reader (zlib)" {
  let key = @api.generate_key("C <c@example.com>", bits=2048)
  // Highly compressible payload: the wire form must be smaller than the
  // plaintext, proving the Compressed packet actually wrapped it.
  let data = @primitives.utf8_bytes("zlib payload ".repeat(2000))
  let msg = @api.encrypt_to_recipients(
    data,
    [key.to_public()],
    compress=@compress.Zlib,
  )
  assert_true(@primitives.utf8_bytes(msg).length() < data.length())
  let (out, status) = @api.decrypt_and_verify(msg, [key], None)
  assert_eq(out, data)
  assert_eq(status, @api.NotSigned)
}

///|
test "compressed output round-trips (zip) and the builder honors compress" {
  let key = @api.generate_key("C2 <c2@example.com>", bits=2048)
  let data = @primitives.utf8_bytes("zip payload ".repeat(2000))
  let encrypt = @api.pgp()
    .encryption()
    .recipient(key.to_public())
    .compress(@compress.Zip)
    .finish()
  let msg = encrypt(data)
  assert_true(@primitives.utf8_bytes(msg).length() < data.length())
  let decrypt = @api.pgp().decryption().decryption_key(key).finish()
  match decrypt(msg) {
    @api.Data(d) => assert_eq(d, data)
    _ => abort("unexpected decrypt result")
  }
}

///|
test "compressed password-encrypted output round-trips" {
  let data = @primitives.utf8_bytes("password zlib payload ".repeat(1000))
  let msg = @api.encrypt_with_password(
    data,
    "compress pass",
    compress=@compress.Zlib,
  )
  let out = @api.decrypt_with_password(msg, "compress pass")
  assert_eq(out, data)
}

///|
test "decompressed payload is capped (negative gate)" {
  // zlib_compress of 64 KiB of zeros inflates far beyond a 1 KiB cap;
  // the capped reader must refuse before handing the payload on.
  let bomb = @compress.zlib_compress(Bytes::make(65536, b'\x00'))
  let raised = try {
    let _ = @compress.zlib_decompress_capped(bomb.exact_view(), 1024)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Under the cap it decompresses normally.
  assert_eq(
    @compress.zlib_decompress_capped(bomb.exact_view(), 1 << 20).length(),
    65536,
  )
  let zbomb = @compress.zip_compress(Bytes::make(65536, b'\x00'))
  let raised2 = try {
    let _ = @compress.zip_decompress_capped(zbomb.exact_view(), 1024)
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
}

///|
test "decrypt entry points enforce the decompression ceiling" {
  let key = @api.generate_key("Bomb <b@example.com>", bits=2048)
  let data = Bytes::make(65536, b'\x00')
  let msg = @api.encrypt_to_recipients(
    data,
    [key.to_public()],
    compress=@compress.Zlib,
  )
  // Default ceiling (512 MiB) leaves it alone.
  assert_eq(@api.decrypt_with_private_key(msg, key).length(), 65536)
  // A 1 KiB override must refuse the 64 KiB expansion.
  let raised = try {
    let _ = @api.decrypt_with_private_key(msg, key, max_decompressed=1024)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // The builder override behaves the same.
  let decrypt = @api.pgp()
    .decryption()
    .decryption_key(key)
    .max_decompressed(1024)
    .finish()
  let raised2 = try {
    let _ = decrypt(msg)
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
}
