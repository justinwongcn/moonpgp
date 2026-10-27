///|
/// BZip2 decode fixtures: produced once with the system bzip2 1.0.8
/// (`bzip2 -9` for text/random, `bzip2 -1` for the 250k input that
/// spans three 100k blocks, and an empty stream), deterministic inputs
/// recorded in the testdata files themselves. The decoder must reproduce
/// the originals byte for byte — the block and stream CRC checks inside
/// the decoder make any mis-decode loud.

///|
test "bzip2: empty stream decodes to empty output" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_empty.bz2")
  assert_eq(@compress.bzip2_decompress(data.exact_view()).length(), 0)
}

///|
test "bzip2: repetitive text with runs and huffman tables" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let plain = @fs.read_file_to_bytes("testdata/bzip2_text.txt")
  assert_eq(@compress.bzip2_decompress(data.exact_view()), plain)
}

///|
test "bzip2: incompressible random bytes" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_random1.bin.bz2")
  let plain = @fs.read_file_to_bytes("testdata/bzip2_random1.bin")
  assert_eq(@compress.bzip2_decompress(data.exact_view()), plain)
}

///|
test "bzip2: multi-block stream" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_multi.bin.bz2")
  let plain = @fs.read_file_to_bytes("testdata/bzip2_multi.bin")
  assert_eq(@compress.bzip2_decompress(data.exact_view()), plain)
}

///|
test "bzip2: output cap is enforced" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let raised = try {
    let _ = @compress.bzip2_decompress_capped(data.exact_view(), 1000)
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("exceeds the 1000-octet limit"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: corrupted payload fails loudly (CRC or structure)" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let corrupted = data[0:20]
    .to_owned()
    .add(Bytes::from_array([(data[20].to_int() ^ 0xFF).to_byte()]))
    .add(data[21:data.length()].to_owned())
  let raised = try {
    let _ = @compress.bzip2_decompress(corrupted.exact_view())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "bzip2: non-stream input is rejected" {
  let raised = try {
    let _ = @compress.bzip2_decompress(
      @primitives.utf8_bytes("definitely not bzip2").exact_view(),
    )
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("not a bzip2 stream"))
      true
    }
  }
  assert_true(raised)
}
