///|
/// BZip2 (RFC 9580 §9.4 compression algorithm 3) decompression in pure
/// MoonBit — the format gpg emits when configured with
/// `--compress-algo bzip2`. The decoder follows the reference
/// implementation's structure: MSB-first bit reader, symbol map,
/// MTF-coded Huffman table selectors, canonical Huffman decode of the
/// MTF/RLE2 symbol stream, the inverse Burrows-Wheeler transform, and
/// the leading run-length layer, with the block CRC and the combined
/// stream CRC both verified on the way out.
///
/// Encoding stays out of scope: this library only ever produces
/// ZIP/ZLIB (see `maybe_compress_inner`), so BZip2 is decode-only by
/// design. Randomized blocks (a pre-0.9.0 bzip2 feature no current
/// encoder emits) are rejected explicitly.

///|
/// MSB-first bit reader over a byte string.
priv struct BzBits {
  data : BytesView
  mut pos : Int32
}

///|
/// Read `n` bits (n <= 32), most significant bit first.
fn BzBits::get(self : BzBits, n : Int32) -> Int32 raise {
  guard n >= 1 && self.pos + n <= self.data.length() * 8 else {
    @error.malformed("compress: truncated bzip2 stream")
  }
  let mut v = 0
  for _ in 0..<n {
    let byte = self.data[self.pos >> 3].to_int()
    v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
    self.pos += 1
  }
  v
}

///|
/// Read up to 48 bits into an Int64 — wide enough for the 48-bit block
/// magics and the 32-bit CRCs, which do not fit a 31-bit Int.
fn BzBits::get64(self : BzBits, n : Int32) -> Int64 raise {
  guard n >= 1 && n <= 48 && self.pos + n <= self.data.length() * 8 else {
    @error.malformed("compress: truncated bzip2 stream")
  }
  let mut v = 0L
  for _ in 0..<n {
    let byte = self.data[self.pos >> 3].to_int()
    v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1).to_int64()
    self.pos += 1
  }
  v
}

///|
/// The bzip2 CRC-32 table: polynomial 0x04C11DB7, MSB-first, init and
/// final complement 0xFFFFFFFF (distinct from the zlib CRC).
fn bzip2_crc_table() -> FixedArray[Int64] {
  let table : FixedArray[Int64] = FixedArray::make(256, 0L)
  for i in 0..<256 {
    let mut c = i.to_int64() << 24
    for _ in 0..<8 {
      c = if (c & 0x80000000L) != 0L { (c << 1) ^ 0x04C11DB7L } else { c << 1 }
    }
    table[i] = c & 0xFFFFFFFFL
  }
  table
}

///|
fn bzip2_crc_update(
  crc : Int64,
  table : FixedArray[Int64],
  value : Int32,
) -> Int64 {
  let idx = (((crc >> 24) ^ value.to_int64()) & 0xFFL).to_int()
  ((crc << 8) & 0xFFFFFFFFL) ^ table[idx]
}

///|
/// One canonical Huffman decode table for a single selector group:
/// per-length code counts, the canonical first code of each length, and
/// the symbols sorted by (length, symbol) so a code maps to
/// `perm[offset[len] + code - start[len]]`.
priv struct BzHuffman {
  min_len : Int32
  max_len : Int32
  count : FixedArray[Int32]
  start : FixedArray[Int32]
  offset : FixedArray[Int32]
  perm : FixedArray[Int32]
}

///|
/// Build a decode table from per-symbol code lengths (each 1..20, the
/// bzip2 limit). Returns None when the lengths cannot form a valid
/// canonical code (no symbols, or the code space overflows).
fn BzHuffman::make(lengths : FixedArray[Int32]) -> BzHuffman? {
  let count : FixedArray[Int32] = FixedArray::make(21, 0)
  let mut min_len = 21
  let mut max_len = 0
  for i in 0..<lengths.length() {
    let l = lengths[i]
    guard l >= 1 && l <= 20 else { return None }
    count[l] += 1
    if l < min_len {
      min_len = l
    }
    if l > max_len {
      max_len = l
    }
  }
  guard min_len <= 20 else { return None }
  // Canonical first code per length; a wrapped code means the lengths do
  // not describe a prefix code.
  let start : FixedArray[Int32] = FixedArray::make(22, 0)
  let mut code = 0
  for l in 1..<=20 {
    start[l] = code
    code = (code + count[l]) << 1
  }
  guard code >= 0 else { return None }
  let offset : FixedArray[Int32] = FixedArray::make(21, 0)
  let perm : FixedArray[Int32] = FixedArray::make(lengths.length(), 0)
  let mut pp = 0
  for l in 1..<=20 {
    offset[l] = pp
    for i in 0..<lengths.length() {
      if lengths[i] == l {
        perm[pp] = i
        pp += 1
      }
    }
  }
  Some({ min_len, max_len, count, start, offset, perm, })
}

///|
/// Decode one symbol by reading bits until the running value lands in
/// the canonical code range of some length. A value that stays outside
/// every range through max_len means corruption, not a valid symbol.
fn BzHuffman::decode(self : BzHuffman, bits : BzBits) -> Int32 raise {
  let mut code = 0
  let mut len = 0
  while len < self.max_len {
    code = (code << 1) | bits.get(1)
    len += 1
    if len >= self.min_len && self.count[len] > 0 {
      let idx = code - self.start[len]
      if idx >= 0 && idx < self.count[len] {
        return self.perm[self.offset[len] + idx]
      }
    }
  }
  @error.malformed("compress: invalid bzip2 Huffman code")
}

///|
/// The MTF/RLE2 symbol stream of one block: Huffman tables addressed by
/// the MTF-coded selector list, advancing to the next selector every 50
/// decoded symbols (the reference decoder's group size).
priv struct BzSymbolStream {
  tables : Array[BzHuffman]
  selectors : Array[Int32]
  mut group_no : Int32
  mut group_pos : Int32
}

///|
fn BzSymbolStream::decode(self : BzSymbolStream, bits : BzBits) -> Int32 raise {
  if self.group_pos == 0 {
    self.group_no += 1
    guard self.group_no < self.selectors.length() else {
      @error.malformed("compress: bzip2 selector budget exhausted")
    }
    self.group_pos = 50
  }
  self.group_pos -= 1
  self.tables[self.selectors[self.group_no]].decode(bits)
}

///|
/// Decompress a full bzip2 stream under a hard output cap. All bounds
/// follow the reference decoder: at most `level * 100000` octets per
/// block, the MTF/RLE2 stream within the block, and the total
/// decompressed size within `max_out` (the M4 policy, as for zlib).
pub fn bzip2_decompress_capped(
  data : BytesView,
  max_out : Int32,
) -> Bytes raise {
  guard max_out >= 0 else { @error.fail("compress: bad output cap") }
  let bits : BzBits = { data, pos: 0, }
  // Stream header: "BZh" + level digit.
  guard bits.get(8) == 0x42 && bits.get(8) == 0x5A && bits.get(8) == 0x68 else {
    @error.malformed("compress: not a bzip2 stream")
  }
  let level_digit = bits.get(8)
  guard level_digit >= 0x31 && level_digit <= 0x39 else {
    @error.malformed("compress: bad bzip2 level digit")
  }
  let block_max = (level_digit - 0x30) * 100000
  let table = bzip2_crc_table()
  let out : Array[Byte] = []
  let mut combined_crc = 0L
  let mut out_len = 0
  // Blocks until the end-of-stream magic.
  for ;; {
    let magic = bits.get64(48)
    if magic == 0x177245385090L {
      // End of stream: verify the combined CRC over all blocks.
      let stored = bits.get64(32) & 0xFFFFFFFFL
      guard combined_crc == stored else {
        @error.malformed("compress: bzip2 stream CRC mismatch")
      }
      break
    }
    guard magic == 0x314159265359L else {
      @error.malformed("compress: bad bzip2 block magic")
    }
    let block_crc = bits.get64(32) & 0xFFFFFFFFL
    // Randomized blocks are a pre-0.9.0 bzip2 relic no current encoder
    // produces; refuse them rather than half-implement the PRNG.
    guard bits.get(1) == 0 else {
      @error.unsupported("compress: randomized bzip2 blocks are not supported")
    }
    let orig_ptr = bits.get(24)
    // Symbol map: a 16-bit mask over 16-symbol groups, then one 16-bit
    // mask per used group, both MSB-first.
    let in_use : FixedArray[Bool] = FixedArray::make(256, false)
    let used_groups = bits.get(16)
    for g in 0..<16 {
      if ((used_groups >> (15 - g)) & 1) == 1 {
        let group_bits = bits.get(16)
        for j in 0..<16 {
          if ((group_bits >> (15 - j)) & 1) == 1 {
            in_use[g * 16 + j] = true
          }
        }
      }
    }
    let seq : Array[Int32] = []
    for s in 0..<256 {
      if in_use[s] {
        seq.push(s)
      }
    }
    let n_in_use = seq.length()
    guard n_in_use >= 1 else {
      @error.malformed("compress: empty bzip2 symbol map")
    }
    let alpha_size = n_in_use + 2
    let n_groups = bits.get(3)
    guard n_groups >= 2 && n_groups <= 6 else {
      @error.malformed("compress: bad bzip2 Huffman group count")
    }
    let n_selectors = bits.get(15)
    // Each selector covers 50 symbols, and the MTF/RLE2 stream can never
    // exceed the block size, so more selectors than that is corruption.
    guard n_selectors <= block_max / 50 + 2 else {
      @error.malformed("compress: too many bzip2 selectors")
    }
    // Selectors arrive MTF-coded over the group list: j one-bits then a
    // zero names position j, which moves to the front (descending shift).
    let pos : Array[Int32] = [0, 1, 2, 3, 4, 5]
    let selectors : Array[Int32] = []
    for _ in 0..<n_selectors {
      let mut j = 0
      for ;; {
        if bits.get(1) == 0 {
          break
        }
        j += 1
        guard j < n_groups else {
          @error.malformed("compress: bzip2 selector out of range")
        }
      }
      let v = pos[j]
      let mut k = j
      while k >= 1 {
        pos[k] = pos[k - 1]
        k = k - 1
      }
      pos[0] = v
      selectors.push(v)
    }
    // Per-group code lengths, delta-coded from a 5-bit seed; the guard
    // after each symbol's delta run pins the 1..20 range (the reference
    // checks there too).
    let tables : Array[BzHuffman] = []
    for _ in 0..<n_groups {
      let lengths : FixedArray[Int32] = FixedArray::make(alpha_size, 0)
      let mut curr = bits.get(5)
      for i in 0..<alpha_size {
        for ;; {
          if bits.get(1) == 0 {
            break
          }
          curr += if bits.get(1) == 0 { 1 } else { -1 }
        }
        guard curr >= 1 && curr <= 20 else {
          @error.malformed("compress: bzip2 code length out of range")
        }
        lengths[i] = curr
      }
      match BzHuffman::make(lengths) {
        Some(t) => tables.push(t)
        None => @error.malformed("compress: invalid bzip2 Huffman table")
      }
    }
    // MTF/RLE2 decode into the BWT string.
    let mtf : FixedArray[Int32] = FixedArray::make(n_in_use, 0)
    for i in 0..<n_in_use {
      mtf[i] = seq[i]
    }
    let stream : BzSymbolStream = {
      tables,
      selectors,
      group_no: -1,
      group_pos: 0,
    }
    let bwt : Array[Int32] = []
    let eob = alpha_size - 1
    let mut block_len = 0
    for ;; {
      let mut sym = stream.decode(bits)
      if sym <= 1 {
        // RUNA/RUNB: bijective base-2 run length of the current MTF front,
        // emitted without moving the front.
        let mut run = 0
        let mut bit = 1
        while sym <= 1 {
          run += if sym == 0 { bit } else { bit << 1 }
          bit = bit << 1
          guard run <= block_max else {
            @error.malformed("compress: bzip2 run exceeds the block size")
          }
          sym = stream.decode(bits)
        }
        guard block_len + run <= block_max else {
          @error.malformed("compress: bzip2 block exceeds its size limit")
        }
        let v = mtf[0]
        for _ in 0..<run {
          bwt.push(v)
          block_len += 1
        }
      }
      if sym == eob {
        break
      }
      // A plain symbol: MTF index (sym - 1), moved to the front
      // (descending shift, as the reference does).
      let idx = sym - 1
      guard idx >= 0 && idx < n_in_use else {
        @error.malformed("compress: bzip2 MTF index out of range")
      }
      let v = mtf[idx]
      let mut k = idx
      while k >= 1 {
        mtf[k] = mtf[k - 1]
        k = k - 1
      }
      mtf[0] = v
      bwt.push(v)
      block_len += 1
      guard block_len <= block_max else {
        @error.malformed("compress: bzip2 block exceeds its size limit")
      }
    }
    guard block_len >= 1 && orig_ptr < block_len else {
      @error.malformed("compress: bad bzip2 block length")
    }
    // Inverse BWT (the reference decoder's tt formulation): tt[i] starts
    // as the BWT octet; ranking each octet overlays the high bits with
    // the position whose sorted rank maps back, and the walk
    // t = tt[t] emits the block through the leading RLE layer.
    let tt : FixedArray[Int32] = FixedArray::make(block_len, 0)
    for i in 0..<block_len {
      tt[i] = bwt[i]
    }
    let cftab : FixedArray[Int32] = FixedArray::make(257, 0)
    for i in 0..<block_len {
      cftab[(tt[i] & 0xFF) + 1] += 1
    }
    for s in 1..<=256 {
      cftab[s] += cftab[s - 1]
    }
    for i in 0..<block_len {
      let uc = tt[i] & 0xFF
      tt[cftab[uc]] = tt[cftab[uc]] | (i << 8)
      cftab[uc] += 1
    }
    let mut t_pos = tt[orig_ptr] >> 8
    // RLE1 + CRC: four equal octets are followed by a repeat count
    // (0-255) naming how many MORE copies follow; the CRC runs over the
    // fully decoded block bytes.
    let mut crc = 0xFFFFFFFFL
    let mut state_len = 0
    let mut state_ch = 0
    for _ in 0..<block_len {
      t_pos = tt[t_pos]
      let uc = t_pos & 0xFF
      t_pos = t_pos >> 8
      if state_len == 4 {
        for _ in 0..<uc {
          out_len = emit_bzip2_byte(out, state_ch, max_out, out_len)
          crc = bzip2_crc_update(crc, table, state_ch)
        }
        state_len = 0
      } else if state_len > 0 && uc == state_ch {
        out_len = emit_bzip2_byte(out, uc, max_out, out_len)
        crc = bzip2_crc_update(crc, table, uc)
        state_len += 1
      } else {
        out_len = emit_bzip2_byte(out, uc, max_out, out_len)
        crc = bzip2_crc_update(crc, table, uc)
        state_ch = uc
        state_len = 1
      }
    }
    guard (crc ^ 0xFFFFFFFFL) == block_crc else {
      @error.malformed("compress: bzip2 block CRC mismatch")
    }
    combined_crc = (((combined_crc << 1) | (combined_crc >> 31)) ^ block_crc) &
      0xFFFFFFFFL
  }
  Bytes::from_array(out)
}

///|
/// Append one decoded octet, enforcing the output cap before the byte
/// materializes so a bomb never gets allocated (M4 policy). Returns the
/// updated output length.
fn emit_bzip2_byte(
  out : Array[Byte],
  value : Int32,
  max_out : Int32,
  out_len : Int32,
) -> Int32 raise {
  guard out_len < max_out else {
    @error.fail(
      "compress: decompressed output exceeds the \{max_out}-octet limit",
    )
  }
  out.push(value.to_byte())
  out_len + 1
}

///|
/// Decompress a full bzip2 stream without an explicit cap. Callers
/// inside the packet walk always use the capped form; this variant
/// exists for parity with `zip_decompress` / `zlib_decompress`.
pub fn bzip2_decompress(data : BytesView) -> Bytes raise {
  bzip2_decompress_capped(data, 0x7FFFFFF0)
}
