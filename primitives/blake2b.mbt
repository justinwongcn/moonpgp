///|
/// BLAKE2b (RFC 7693), unkeyed, variable digest length.
///
/// BLAKE2b is not an OpenPGP message-digest algorithm, so it is deliberately
/// absent from `HashId`; it exists here because Argon2 (RFC 9580 §3.7.1.4
/// pins Argon2id) is defined over it. Like every other primitive, the
/// implementation lives in `src/primitives` so the rest of the library never
/// depends on a hash backend directly.

///|
/// BLAKE2b compression-function block size in octets.
const BLAKE2B_BLOCK_SIZE : Int32 = 128

///|
/// BLAKE2b round count for the 64-bit variant.
const BLAKE2B_ROUNDS : Int32 = 12

///|
/// BLAKE2b parameter block XOR constant: digest length in the low byte,
/// key length (always 0 here) in the second byte, fanout=1, depth=1.
const BLAKE2B_PARAM_XOR : UInt64 = 0x01010000UL

///|
/// Rotate a 64-bit word right. `n` must be in 1..63 (all BLAKE2b/Argon2
/// rotations are).
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// The BLAKE2b initialization vector (the SHA-512 IV).
fn blake2b_iv() -> FixedArray[UInt64] {
  [
    0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
    0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL,
  ]
}

///|
/// The BLAKE2b message schedule (RFC 7693 §2.7); rounds 10 and 11 repeat
/// rows 0 and 1, which the `% 10` in the round loop handles.
let blake2b_sigma : FixedArray[Int32] = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
   14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, //
   11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, //
   7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, //
   9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, //
   2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, //
   12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, //
   13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, //
   6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, //
   10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0, //
]

///|
/// Read a 64-bit little-endian word at `off`.
fn read_u64_le(b : ArrayView[Byte], off : Int32) -> UInt64 {
  b[off].to_uint64() |
  (b[off + 1].to_uint64() << 8) |
  (b[off + 2].to_uint64() << 16) |
  (b[off + 3].to_uint64() << 24) |
  (b[off + 4].to_uint64() << 32) |
  (b[off + 5].to_uint64() << 40) |
  (b[off + 6].to_uint64() << 48) |
  (b[off + 7].to_uint64() << 56)
}

///|
/// The BLAKE2b mixing function G (RFC 7693 §3.1), operating directly on the
/// working vector.
fn blake2b_g(
  v : FixedArray[UInt64],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt64,
  y : UInt64,
) -> Unit {
  let va = v[a] + v[b] + x
  let vd = rotr64(v[d] ^ va, 32)
  let vc = v[c] + vd
  let vb = rotr64(v[b] ^ vc, 24)
  let va2 = va + vb + y
  let vd2 = rotr64(vd ^ va2, 16)
  let vc2 = vc + vd2
  let vb2 = rotr64(vb ^ vc2, 63)
  v[a] = va2
  v[b] = vb2
  v[c] = vc2
  v[d] = vd2
}

///|
/// The BLAKE2b compression function F (RFC 7693 §3.2). `block` is exactly
/// 128 octets; `t` is the number of message octets processed so far
/// (including this block); `last` toggles the finalization flag.
fn blake2b_compress(
  h : FixedArray[UInt64],
  block : ArrayView[Byte],
  t : UInt64,
  last : Bool,
) -> Unit {
  let m : FixedArray[UInt64] = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    m[i] = read_u64_le(block, i * 8)
  }
  let iv = blake2b_iv()
  let v : FixedArray[UInt64] = FixedArray::make(16, 0UL)
  for i in 0..<8 {
    v[i] = h[i]
    v[i + 8] = iv[i]
  }
  v[12] = v[12] ^ t
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFUL
  }
  for r in 0..<BLAKE2B_ROUNDS {
    let s = r % 10 * 16
    blake2b_g(v, 0, 4, 8, 12, m[blake2b_sigma[s]], m[blake2b_sigma[s + 1]])
    blake2b_g(v, 1, 5, 9, 13, m[blake2b_sigma[s + 2]], m[blake2b_sigma[s + 3]])
    blake2b_g(v, 2, 6, 10, 14, m[blake2b_sigma[s + 4]], m[blake2b_sigma[s + 5]])
    blake2b_g(v, 3, 7, 11, 15, m[blake2b_sigma[s + 6]], m[blake2b_sigma[s + 7]])
    blake2b_g(v, 0, 5, 10, 15, m[blake2b_sigma[s + 8]], m[blake2b_sigma[s + 9]])
    blake2b_g(
      v,
      1,
      6,
      11,
      12,
      m[blake2b_sigma[s + 10]],
      m[blake2b_sigma[s + 11]],
    )
    blake2b_g(
      v,
      2,
      7,
      8,
      13,
      m[blake2b_sigma[s + 12]],
      m[blake2b_sigma[s + 13]],
    )
    blake2b_g(
      v,
      3,
      4,
      9,
      14,
      m[blake2b_sigma[s + 14]],
      m[blake2b_sigma[s + 15]],
    )
  }
  for i in 0..<8 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
/// Streaming BLAKE2b state (private; callers use `blake2b` or `Blake2b`).
priv struct Blake2bState {
  h : FixedArray[UInt64]
  buf : Array[Byte]
  mut buflen : Int32
  /// Message octets already fed through the compression function.
  mut t : UInt64
  out_len : Int32
}

///|
fn Blake2bState::new(out_len : Int32) -> Blake2bState {
  let h = blake2b_iv()
  h[0] = h[0] ^ (BLAKE2B_PARAM_XOR ^ out_len.to_uint64())
  {
    h,
    buf: Array::make(BLAKE2B_BLOCK_SIZE, b'\x00'),
    buflen: 0,
    t: 0UL,
    out_len,
  }
}

///|
fn Blake2bState::update(self : Blake2bState, data : ArrayView[Byte]) -> Unit {
  for i in 0..<data.length() {
    if self.buflen == BLAKE2B_BLOCK_SIZE {
      self.t = self.t + BLAKE2B_BLOCK_SIZE.to_uint64()
      blake2b_compress(self.h, self.buf[:], self.t, false)
      self.buflen = 0
    }
    self.buf[self.buflen] = data[i]
    self.buflen = self.buflen + 1
  }
}

///|
fn Blake2bState::finalize(self : Blake2bState) -> Bytes {
  self.t = self.t + self.buflen.to_uint64()
  for i in self.buflen..<BLAKE2B_BLOCK_SIZE {
    self.buf[i] = b'\x00'
  }
  blake2b_compress(self.h, self.buf[:], self.t, true)
  let out : Array[Byte] = Array(capacity=64)
  for i in 0..<8 {
    for b in self.h[i].to_le_bytes() {
      out.push(b)
    }
  }
  Bytes::from_array(out[0:self.out_len])
}

///|
/// BLAKE2b with an explicit digest length `out_len` (1..64), unkeyed, over
/// `data`. Argon2 calls this with 64 and with smaller sizes for its H'
/// variable-length hash.
///
/// # Example
/// ```mbt check
/// test {
///   let digest = @primitives.blake2b(b"abc", 64)
///   inspect(
///     @primitives.to_hex(digest),
///     content=(
///       #|ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
///     ),
///   )
/// }
/// ```
pub fn blake2b(data : BytesView, out_len : Int32) -> Bytes raise {
  guard out_len >= 1 && out_len <= 64 else {
    @error.fail("blake2b: digest length must be 1..64")
  }
  let st = Blake2bState::new(out_len)
  st.update(data.to_owned().to_array())
  st.finalize()
}
