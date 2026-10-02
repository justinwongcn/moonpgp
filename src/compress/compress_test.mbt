///|
test "zip roundtrip" {
  let data = @primitives.utf8_bytes("compress me please, compress me please!")
  let z = @compress.zip_compress(data.view())
  assert_true(z.length() < data.length())
  assert_eq(@compress.zip_decompress(z.view()), data)
}

///|
test "zlib roundtrip" {
  let data = @primitives.utf8_bytes("zlib wrapped data zlib wrapped data")
  let z = @compress.zlib_compress(data.view())
  assert_eq(@compress.zlib_decompress(z.view()), data)
}

///|
test "inflate real deflate stream (fixed huffman)" {
  // Raw DEFLATE of "hello openpgp" generated with Python zlib (level 9,
  // raw window). Different encoders may emit different streams; the
  // decompressor must accept any valid stream.
  let stream = @primitives.from_hex("cb48cdc9c957c82f48cd2b482f0000")
  let out = @compress.zip_decompress(stream.view())
  assert_eq(out, @primitives.utf8_bytes("hello openpgp"))
}
