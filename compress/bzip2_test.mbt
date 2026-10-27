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

///|
/// MSB-first bit writer for crafting malformed streams the tests below
/// feed to the decoder: every guard the happy-path fixtures cannot reach
/// gets a deterministic hand-built bitstream.
priv struct BzBitsOut {
  buf : Array[Byte]
  mut bit : Int32
}

///|
fn BzBitsOut::put(self : BzBitsOut, n : Int32, value : Int32) -> Unit {
  for i in 0..<n {
    let shift = n - 1 - i
    let bit = (value >> shift) & 1
    if self.bit % 8 == 0 {
      self.buf.push(b'\x00')
    }
    let idx = self.buf.length() - 1
    if bit == 1 {
      self.buf[idx] = (self.buf[idx].to_int() | (1 << (7 - self.bit % 8))).to_byte()
    }
    self.bit += 1
  }
}

///|
fn BzBitsOut::to_bytes(self : BzBitsOut) -> Bytes {
  Bytes::from_array(self.buf)
}

///|
/// "BZh1" + one block preamble: block magic, a stored block CRC (garbage
/// is fine — the tests decide below whether decoding gets that far), the
/// randomized bit clear and an origin pointer.
fn bz_block_preamble(crc : Int32) -> BzBitsOut {
  let w : BzBitsOut = { buf: [], bit: 0, }
  for ch in [0x42, 0x5A, 0x68, 0x31] {
    w.put(8, ch)
  }
  w.put(24, 0x314159)
  w.put(24, 0x265359)
  w.put(32, crc)
  w.put(1, 0)
  w.put(24, 0)
  w
}

///|
test "bzip2: truncated stream is rejected, not partially decoded" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let clipped = data[0:data.length() - 1].to_owned()
  let raised = try {
    let _ = @compress.bzip2_decompress(clipped.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("truncated bzip2 stream"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a wrong stored block CRC fails the block check" {
  // Bytes 10..13 hold the first block's stored CRC; flipping a bit there
  // leaves the block data untouched, so decoding runs to completion and
  // must die at exactly the block CRC comparison.
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let corrupted = data[0:10]
    .to_owned()
    .add(Bytes::from_array([(data[10].to_int() ^ 0x01).to_byte()]))
    .add(data[11:data.length()].to_owned())
  let raised = try {
    let _ = @compress.bzip2_decompress(corrupted.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("block CRC mismatch"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a wrong stored stream CRC fails the final check" {
  // The empty stream is exactly header + end magic + CRC; flipping a bit
  // in the stored CRC (byte 10) leaves a fully decodable stream whose
  // combined CRC no longer matches.
  let data = @fs.read_file_to_bytes("testdata/bzip2_empty.bz2")
  let corrupted = data[0:10]
    .to_owned()
    .add(Bytes::from_array([(data[10].to_int() ^ 0x01).to_byte()]))
    .add(data[11:data.length()].to_owned())
  let raised = try {
    let _ = @compress.bzip2_decompress(corrupted.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("stream CRC mismatch"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: randomized blocks are refused" {
  // Byte 14 is the first octet after the block preamble up to the CRC;
  // its top bit is the randomized flag of the text fixture's first block.
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let corrupted = data[0:14]
    .to_owned()
    .add(Bytes::from_array([(data[14].to_int() | 0x80).to_byte()]))
    .add(data[15:data.length()].to_owned())
  let raised = try {
    let _ = @compress.bzip2_decompress(corrupted.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("randomized bzip2 blocks"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a corrupt block magic is rejected" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let corrupted = data[0:4]
    .to_owned()
    .add(Bytes::from_array([(data[4].to_int() ^ 0x01).to_byte()]))
    .add(data[5:data.length()].to_owned())
  let raised = try {
    let _ = @compress.bzip2_decompress(corrupted.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("bad bzip2 block magic"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: an out-of-range level digit is rejected" {
  let data = @fs.read_file_to_bytes("testdata/bzip2_empty.bz2")
  let bad_level = Bytes::from_array([0x42, 0x5A, 0x68, 0x30]).add(
    data[4:data.length()].to_owned(),
  )
  let raised = try {
    let _ = @compress.bzip2_decompress(bad_level.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("bad bzip2 level digit"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: an empty symbol map is rejected" {
  // Valid block preamble, then a 16-bit group mask of zero: no symbols
  // at all, which no encoder can produce.
  let w = bz_block_preamble(0)
  w.put(16, 0)
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("empty bzip2 symbol map"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a bad Huffman group count is rejected" {
  // One in-use symbol ('a'), then the 3-bit group count of 7 (legal: 2-6).
  let w = bz_block_preamble(0)
  w.put(16, 1)
  w.put(16, 1)
  w.put(3, 7)
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("bad bzip2 Huffman group count"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a selector index beyond the group count is rejected" {
  // nGroups=2, one selector, and its unary code runs past the table.
  let w = bz_block_preamble(0)
  w.put(16, 1)
  w.put(16, 1)
  w.put(3, 2)
  w.put(15, 1)
  w.put(1, 1)
  w.put(1, 1)
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("selector"))
      true
    }
  }
  assert_true(raised)
}

///|
/// A one-symbol alphabet ('a') with Huffman code lengths [1,2,2] gives
/// RUNA=0, RUNB=10, EOB=11 — the minimal bitstream that reaches the
/// decode loop, enough to pin the guards no real encoder can hit.
fn bz_single_symbol_stream() -> BzBitsOut {
  let w = bz_block_preamble(0)
  w.put(16, 1)
  w.put(16, 1)
  w.put(3, 2)
  w.put(15, 1)
  w.put(1, 0)
  // nGroups=2 means TWO tables follow; both encode lengths [1,2,2]
  // (RUNA break, RUNB continue/delta(+1)/break, EOB break).
  for _ in 0..<2 {
    w.put(5, 1)
    w.put(1, 0)
    w.put(1, 1)
    w.put(1, 0)
    w.put(1, 0)
    w.put(1, 0)
  }
  w
}

///|
test "bzip2: a block that ends before any data is rejected" {
  let w = bz_single_symbol_stream()
  w.put(1, 1)
  w.put(1, 1)
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("bad bzip2 block length"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a run longer than the block size is rejected" {
  let w = bz_single_symbol_stream()
  // Seventeen RUNA symbols accumulate a run of 2^17 - 1, past the
  // 100000-octet block of the level-1 stream.
  for _ in 0..<17 {
    w.put(1, 0)
  }
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("run exceeds the block size"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: more selectors than the block can use is rejected" {
  let w = bz_block_preamble(0)
  w.put(16, 1)
  w.put(16, 1)
  w.put(3, 2)
  // 3000 selectors for a level-1 block: the budget is block_max/50 + 2.
  w.put(15, 3000)
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("too many bzip2 selectors"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: a bit pattern outside every Huffman code is rejected" {
  let w = bz_block_preamble(0)
  w.put(16, 1)
  w.put(16, 1)
  w.put(3, 2)
  w.put(15, 1)
  w.put(1, 0)
  // Code lengths [2,2,2] in both tables: codes 00/01/10; the pattern 11
  // completes no code.
  for _ in 0..<2 {
    w.put(5, 2)
    w.put(1, 0)
    w.put(1, 0)
    w.put(1, 0)
  }
  w.put(1, 1)
  w.put(1, 1)
  let raised = try {
    let _ = @compress.bzip2_decompress(w.to_bytes().exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("invalid bzip2 Huffman code"))
      true
    }
  }
  assert_true(raised)
}

///|
test "bzip2: truncation inside a short bit field is rejected too" {
  // Clipped mid-block-header, the next 24-bit origin-pointer read runs
  // out of bits — the same guard family as the stream-tail truncation.
  let data = @fs.read_file_to_bytes("testdata/bzip2_text.txt.bz2")
  let clipped = data[0:15].to_owned()
  let raised = try {
    let _ = @compress.bzip2_decompress(clipped.exact_view())
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("truncated bzip2 stream"))
      true
    }
  }
  assert_true(raised)
}
