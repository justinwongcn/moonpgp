///|
/// Argon2id (RFC 9106) with version 0x13, unkeyed BLAKE2b, and empty secret
/// and associated data — exactly the configuration RFC 9580 §3.7.1.4 pins
/// for the S2K specifier type 4.
///
/// The implementation is single-threaded: filling slice by slice, lane by
/// lane, is equivalent to the threaded reference because slices are the
/// only synchronisation barrier and a lane never references blocks of the
/// current slice in another lane during pass 0 slice 0 (RFC 9106 §3.4).

///|
/// Hard ceiling on Argon2 memory, in KiB: 2^21 KiB = 2 GiB, the first
/// RFC 9106 §4 recommended Argon2id option and what RFC 9580 Appendix A.5
/// and A.12 use. A 20-octet S2K specifier can ask for up to 2^31 KiB, so
/// callers must never allocate an attacker-chosen size unchecked.
pub const ARGON2_MAX_MEMORY_KIB : Int32 = 2097152

///|
/// Default Argon2 memory policy (KiB) for the public decrypt entry points:
/// 2^16 KiB = 64 MiB (S7).
///
/// An Argon2 S2K specifier is attacker-controlled and the derivation runs
/// *before* any authentication, so the cap decides how much memory one
/// unauthenticated message can cost — and a malicious SKESK may pair the
/// full cap with up to 255 passes, multiplying both memory and CPU. The
/// 64 MiB default matches the profile every mainstream writer defaults to
/// (go-crypto/gopenpgp, OpenPGP.js), so ordinary interop never needs to
/// raise it, while GnuPG cannot produce an Argon2 S2K at all.
///
/// Messages that genuinely ask for more — RFC 9580 Appendix A.5/A.12 use
/// the RFC 9106 first recommended option (2 GiB, `ARGON2_MAX_MEMORY_KIB`)
/// — must pass the wider policy explicitly:
///
///   decrypt_with_password(msg, pass, argon2_max_memory_kib=@primitives.ARGON2_MAX_MEMORY_KIB)
///
/// `scripts/acceptance.sh` and the `slow:*` tests do exactly that, so the
/// widened call is exercised by the release gate.
pub const DEFAULT_ARGON2_MAX_MEMORY_KIB : Int32 = 65536

///|
/// Argon2 version pinned by RFC 9580 (the current 1.3 version).
const ARGON2_VERSION : Int32 = 0x13

///|
/// Argon2 type id for Argon2id (0=d, 1=i, 2=id).
const ARGON2_TYPE_ID : Int32 = 2

///|
/// One Argon2 block is 128 64-bit words (1024 octets).
const ARGON2_BLOCK_WORDS : Int32 = 128

///|
/// Words between regenerations of the Argon2i address block.
const ARGON2_ADDRESSES_IN_BLOCK : Int32 = 128

///|
/// Number of slices (synchronisation points) per pass.
const ARGON2_SYNC_POINTS : Int32 = 4

///|
/// The mutable working set of one Argon2 invocation.
priv struct Argon2Instance {
  /// All `m'` blocks, laid out block-major (`block * 128 + word`).
  mem : FixedArray[UInt64]
  /// 128-word scratch for the compression function.
  scratch : FixedArray[UInt64]
  /// Argon2i address block.
  addr : FixedArray[UInt64]
  /// Argon2i input block.
  input : FixedArray[UInt64]
  /// All-zero block used by `next_addresses`.
  zero : FixedArray[UInt64]
  lanes : Int32
  /// Rounded block count actually allocated (a multiple of 4*lanes).
  m_prime : Int32
  /// Blocks per lane.
  lane_len : Int32
  /// Blocks per slice (a quarter of a lane).
  segment_len : Int32
}

///|
fn argon2_instance(lanes : Int32, m_prime : Int32) -> Argon2Instance {
  let lane_len = m_prime / lanes
  {
    mem: FixedArray::make(m_prime * ARGON2_BLOCK_WORDS, 0UL),
    scratch: FixedArray::make(ARGON2_BLOCK_WORDS, 0UL),
    addr: FixedArray::make(ARGON2_BLOCK_WORDS, 0UL),
    input: FixedArray::make(ARGON2_BLOCK_WORDS, 0UL),
    zero: FixedArray::make(ARGON2_BLOCK_WORDS, 0UL),
    lanes,
    m_prime,
    lane_len,
    segment_len: lane_len / ARGON2_SYNC_POINTS,
  }
}

///|
/// The BlaMka mixing function GB (RFC 9106 §3.6): the BLAKE2b G with the
/// `2 * trunc(a) * trunc(b)` term added to each addition, operating on four
/// words of `b` in place.
fn blamka_gb(
  b : FixedArray[UInt64],
  i : Int32,
  j : Int32,
  k : Int32,
  l : Int32,
) -> Unit {
  let mut a = b[i]
  let mut bb = b[j]
  let mut c = b[k]
  let mut d = b[l]
  a = a + bb + 2UL * (a & 0xFFFFFFFFUL) * (bb & 0xFFFFFFFFUL)
  d = rotr64(d ^ a, 32)
  c = c + d + 2UL * (c & 0xFFFFFFFFUL) * (d & 0xFFFFFFFFUL)
  bb = rotr64(bb ^ c, 24)
  a = a + bb + 2UL * (a & 0xFFFFFFFFUL) * (bb & 0xFFFFFFFFUL)
  d = rotr64(d ^ a, 16)
  c = c + d + 2UL * (c & 0xFFFFFFFFUL) * (d & 0xFFFFFFFFUL)
  bb = rotr64(bb ^ c, 63)
  b[i] = a
  b[j] = bb
  b[k] = c
  b[l] = d
}

///|
/// The Argon2 permutation P on 16 words identified by their indices
/// (RFC 9106 §3.6).
fn argon2_round(
  b : FixedArray[UInt64],
  i0 : Int32,
  i1 : Int32,
  i2 : Int32,
  i3 : Int32,
  i4 : Int32,
  i5 : Int32,
  i6 : Int32,
  i7 : Int32,
  i8 : Int32,
  i9 : Int32,
  i10 : Int32,
  i11 : Int32,
  i12 : Int32,
  i13 : Int32,
  i14 : Int32,
  i15 : Int32,
) -> Unit {
  blamka_gb(b, i0, i4, i8, i12)
  blamka_gb(b, i1, i5, i9, i13)
  blamka_gb(b, i2, i6, i10, i14)
  blamka_gb(b, i3, i7, i11, i15)
  blamka_gb(b, i0, i5, i10, i15)
  blamka_gb(b, i1, i6, i11, i12)
  blamka_gb(b, i2, i7, i8, i13)
  blamka_gb(b, i3, i4, i9, i14)
}

///|
/// Apply P to all eight rows (contiguous groups of 16 words) and then to
/// all eight columns of the 8x16 word matrix.
fn argon2_permute(b : FixedArray[UInt64]) -> Unit {
  for i in 0..<8 {
    let base = i * 16
    argon2_round(
      b,
      base + 0,
      base + 1,
      base + 2,
      base + 3,
      base + 4,
      base + 5,
      base + 6,
      base + 7,
      base + 8,
      base + 9,
      base + 10,
      base + 11,
      base + 12,
      base + 13,
      base + 14,
      base + 15,
    )
  }
  for i in 0..<8 {
    let c = 2 * i
    argon2_round(
      b,
      c,
      c + 1,
      c + 16,
      c + 17,
      c + 32,
      c + 33,
      c + 48,
      c + 49,
      c + 64,
      c + 65,
      c + 80,
      c + 81,
      c + 96,
      c + 97,
      c + 112,
      c + 113,
    )
  }
}

///|
/// The Argon2 compression function G over blocks in the main memory array:
/// `G(prev, ref) = P(prev XOR ref) XOR (prev XOR ref)`. For version 0x13 and
/// any pass after the first, RFC 9106 §3.4 XORs the block being replaced
/// into the result, so `B[i][j] = G(B[i][j-1], B[l][z]) XOR B[i][j](old)`.
///
/// `out` never aliases `prev` or `ref` here, so the old value can be read
/// back in place just before it is overwritten.
fn argon2_fill_block(
  inst : Argon2Instance,
  prev_off : Int32,
  ref_off : Int32,
  out_off : Int32,
  with_xor : Bool,
) -> Unit {
  let mem = inst.mem
  let s = inst.scratch
  for k in 0..<ARGON2_BLOCK_WORDS {
    s[k] = mem[prev_off + k] ^ mem[ref_off + k]
  }
  argon2_permute(s)
  for k in 0..<ARGON2_BLOCK_WORDS {
    let mut v = s[k] ^ mem[prev_off + k] ^ mem[ref_off + k]
    if with_xor {
      v = v ^ mem[out_off + k]
    }
    mem[out_off + k] = v
  }
}

///|
/// The same compression function for standalone blocks (the Argon2i address
/// generation), where `out` may alias `reference`. Reading the old output
/// before the permutation keeps the aliasing safe.
fn argon2_fill_block_sep(
  inst : Argon2Instance,
  prev : FixedArray[UInt64],
  reference : FixedArray[UInt64],
  out : FixedArray[UInt64],
  with_xor : Bool,
) -> Unit {
  let s = inst.scratch
  let old : FixedArray[UInt64] = FixedArray::make(ARGON2_BLOCK_WORDS, 0UL)
  for k in 0..<ARGON2_BLOCK_WORDS {
    old[k] = out[k]
    s[k] = prev[k] ^ reference[k]
  }
  argon2_permute(s)
  for k in 0..<ARGON2_BLOCK_WORDS {
    let mut v = s[k] ^ prev[k] ^ reference[k]
    if with_xor {
      v = v ^ old[k]
    }
    out[k] = v
  }
}

///|
/// Argon2i address-block generation (RFC 9106 §3.4.1.2): bump the counter,
/// then `G(0, input)` followed by `G(0, address)`.
fn argon2_next_addresses(inst : Argon2Instance) -> Unit {
  inst.input[6] = inst.input[6] + 1UL
  argon2_fill_block_sep(inst, inst.zero, inst.input, inst.addr, false)
  argon2_fill_block_sep(inst, inst.zero, inst.addr, inst.addr, false)
}

///|
/// The reference-block index selection (RFC 9106 §3.4.1.3, `index_alpha`).
fn argon2_index_alpha(
  inst : Argon2Instance,
  pass : Int32,
  slice : Int32,
  index : Int32,
  j1 : UInt64,
  same_lane : Bool,
) -> Int32 {
  let seg = inst.segment_len
  let lane_len = inst.lane_len
  let reference_area_size : Int32 = if pass == 0 {
    if slice == 0 {
      index - 1
    } else if same_lane {
      slice * seg + index - 1
    } else {
      slice * seg + (if index == 0 { -1 } else { 0 })
    }
  } else if same_lane {
    lane_len - seg + index - 1
  } else {
    lane_len - seg + (if index == 0 { -1 } else { 0 })
  }
  let area = reference_area_size.to_uint64()
  let mut relative_position = j1
  relative_position = (relative_position * relative_position) >> 32
  relative_position = area - 1UL - ((area * relative_position) >> 32)
  let start_position : Int32 = if pass == 0 {
    0
  } else if slice == ARGON2_SYNC_POINTS - 1 {
    0
  } else {
    (slice + 1) * seg
  }
  ((start_position.to_uint64() + relative_position) % lane_len.to_uint64()).to_int()
}

///|
/// Fill one segment: the blocks of `slice` in `lane` for `pass`
/// (RFC 9106 §3.4.1.1).
fn argon2_fill_segment(
  inst : Argon2Instance,
  pass : Int32,
  lane : Int32,
  slice : Int32,
  passes : Int32,
) -> Unit {
  let lanes = inst.lanes
  let seg = inst.segment_len
  let lane_len = inst.lane_len
  // Argon2id: data-independent addressing for the first two slices of the
  // first pass, data-dependent afterwards (RFC 9106 §3.4.1.1).
  let data_independent = pass == 0 && slice < 2
  if data_independent {
    for k in 0..<ARGON2_BLOCK_WORDS {
      inst.input[k] = 0UL
    }
    inst.input[0] = pass.to_uint64()
    inst.input[1] = lane.to_uint64()
    inst.input[2] = slice.to_uint64()
    inst.input[3] = inst.m_prime.to_uint64()
    inst.input[4] = passes.to_uint64()
    inst.input[5] = ARGON2_TYPE_ID.to_uint64()
  }
  let mut starting_index = 0
  if pass == 0 && slice == 0 {
    // Blocks 0 and 1 of every lane are already the H' output.
    starting_index = 2
    if data_independent {
      argon2_next_addresses(inst)
    }
  }
  let mut curr = lane * lane_len + slice * seg + starting_index
  let mut prev = if curr % lane_len == 0 {
    curr + lane_len - 1
  } else {
    curr - 1
  }
  for i in starting_index..<seg {
    if curr % lane_len == 1 {
      prev = curr - 1
    }
    let pseudo_rand : UInt64 = if data_independent {
      if i % ARGON2_ADDRESSES_IN_BLOCK == 0 {
        argon2_next_addresses(inst)
      }
      inst.addr[i % ARGON2_ADDRESSES_IN_BLOCK]
    } else {
      inst.mem[prev * ARGON2_BLOCK_WORDS]
    }
    let j1 = pseudo_rand & 0xFFFFFFFFUL
    let mut ref_lane = ((pseudo_rand >> 32) % lanes.to_uint64()).to_int()
    if pass == 0 && slice == 0 {
      // No other lane has usable data yet.
      ref_lane = lane
    }
    let ref_index = argon2_index_alpha(
      inst,
      pass,
      slice,
      i,
      j1,
      ref_lane == lane,
    )
    argon2_fill_block(
      inst,
      prev * ARGON2_BLOCK_WORDS,
      (ref_lane * lane_len + ref_index) * ARGON2_BLOCK_WORDS,
      curr * ARGON2_BLOCK_WORDS,
      pass > 0,
    )
    curr = curr + 1
    prev = prev + 1
  }
}

///|
/// Append a 32-bit little-endian integer.
fn push_le32(out : Array[Byte], v : Int32) -> Unit {
  out.push((v & 0xFF).to_byte())
  out.push(((v >> 8) & 0xFF).to_byte())
  out.push(((v >> 16) & 0xFF).to_byte())
  out.push(((v >> 24) & 0xFF).to_byte())
}

///|
/// Append a length-prefixed octet string (`LE32(len) || bytes`).
fn push_sized(out : Array[Byte], data : BytesView) -> Unit {
  push_le32(out, data.length())
  for b in data {
    out.push(b)
  }
}

///|
/// Store 128 little-endian words of `data` (1024 octets) at block `off`.
fn argon2_store_block(
  mem : FixedArray[UInt64],
  off : Int32,
  data : BytesView,
) -> Unit {
  let arr = data.to_array()
  let view : ArrayView[Byte] = arr[:]
  for i in 0..<ARGON2_BLOCK_WORDS {
    mem[off + i] = read_u64_le(view, i * 8)
  }
}

///|
/// The 1024-octet little-endian serialization of `len` words of `words`.
fn argon2_words_to_bytes(
  words : FixedArray[UInt64],
  off : Int32,
  len : Int32,
) -> Bytes {
  let out : Array[Byte] = Array(capacity=len * 8)
  for i in off..<(off + len) {
    for b in words[i].to_le_bytes() {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}

///|
/// The Argon2 variable-length hash H' (RFC 9106 §3.3).
fn argon2_h_prime(input : BytesView, out_len : Int32) -> Bytes raise {
  let prefix : Array[Byte] = []
  push_le32(prefix, out_len)
  let head = concat2(Bytes::from_array(prefix), input)
  if out_len <= 64 {
    return blake2b(head, out_len)
  }
  let r = (out_len + 31) / 32 - 2
  let mut v = blake2b(head, 64)
  let out : Array[Byte] = Array(capacity=out_len)
  for i in 0..<r {
    // W_i = the first 32 octets of V_i.
    for k in 0..<32 {
      out.push(v[k])
    }
    if i < r - 1 {
      v = blake2b(v, 64)
    }
  }
  // V_{r+1} has the remaining digest length.
  for b in blake2b(v, out_len - 32 * r) {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// The Argon2 pre-hash H0 (RFC 9106 §3.2), including the optional secret
/// `K` and associated data `X` (both empty for OpenPGP).
fn argon2_h0(
  pass : BytesView,
  salt : BytesView,
  secret : BytesView,
  ad : BytesView,
  tag_len : Int32,
  m_kib : Int32,
  passes : Int32,
  lanes : Int32,
) -> Bytes raise {
  let buf : Array[Byte] = []
  push_le32(buf, lanes)
  push_le32(buf, tag_len)
  push_le32(buf, m_kib)
  push_le32(buf, passes)
  push_le32(buf, ARGON2_VERSION)
  push_le32(buf, ARGON2_TYPE_ID)
  push_sized(buf, pass)
  push_sized(buf, salt)
  push_sized(buf, secret)
  push_sized(buf, ad)
  blake2b(Bytes::from_array(buf), 64)
}

///|
/// Argon2id with a caller-chosen secret and associated data. OpenPGP never
/// uses `secret`/`ad`, but RFC 9106's own known-answer test does, and this
/// is the entry point that reproduces it.
pub fn argon2id_with_secret_ad(
  pass : BytesView,
  salt : BytesView,
  secret : BytesView,
  ad : BytesView,
  passes : Int32,
  m_kib : Int32,
  parallelism : Int32,
  tag_len : Int32,
  max_memory_kib~ : Int32 = ARGON2_MAX_MEMORY_KIB,
) -> Bytes raise {
  guard passes >= 1 else { @error.fail("argon2: passes must be non-zero") }
  guard parallelism >= 1 else {
    @error.fail("argon2: parallelism must be non-zero")
  }
  guard tag_len >= 1 else { @error.fail("argon2: tag length must be non-zero") }
  guard m_kib >= 8 * parallelism else {
    @error.fail("argon2: memory must be at least 8*parallelism KiB")
  }
  guard m_kib <= max_memory_kib else {
    @error.fail(
      "argon2: requested memory \{m_kib} KiB exceeds the cap \{max_memory_kib} KiB",
    )
  }
  guard m_kib <= ARGON2_MAX_MEMORY_KIB else {
    @error.fail(
      "argon2: memory \{m_kib} KiB exceeds the implementation limit \{ARGON2_MAX_MEMORY_KIB} KiB",
    )
  }
  // RFC 9106 §3.1: round the block count down to a multiple of 4*lanes.
  let m_prime = ARGON2_SYNC_POINTS *
    parallelism *
    (m_kib / (ARGON2_SYNC_POINTS * parallelism))
  let inst = argon2_instance(parallelism, m_prime)
  let h0 = argon2_h0(
    pass, salt, secret, ad, tag_len, m_kib, passes, parallelism,
  )
  // B[i][0] and B[i][1] are the H' expansion of H0 with the block index.
  for lane in 0..<parallelism {
    for index in 0..<2 {
      let buf : Array[Byte] = []
      for b in h0 {
        buf.push(b)
      }
      push_le32(buf, index)
      push_le32(buf, lane)
      let block = argon2_h_prime(Bytes::from_array(buf), 1024)
      argon2_store_block(
        inst.mem,
        (lane * inst.lane_len + index) * ARGON2_BLOCK_WORDS,
        block,
      )
    }
  }
  for pass in 0..<passes {
    for slice in 0..<ARGON2_SYNC_POINTS {
      for lane in 0..<parallelism {
        argon2_fill_segment(inst, pass, lane, slice, passes)
      }
    }
  }
  // C = the XOR of the last block of every lane; tag = H'^T(C).
  let c : FixedArray[UInt64] = FixedArray::make(ARGON2_BLOCK_WORDS, 0UL)
  for lane in 0..<parallelism {
    let off = (lane * inst.lane_len + inst.lane_len - 1) * ARGON2_BLOCK_WORDS
    for k in 0..<ARGON2_BLOCK_WORDS {
      c[k] = c[k] ^ inst.mem[off + k]
    }
  }
  let tag = argon2_h_prime(
    argon2_words_to_bytes(c, 0, ARGON2_BLOCK_WORDS),
    tag_len,
  )
  // Best-effort zeroization of the working set before it is collected.
  for i in 0..<inst.mem.length() {
    inst.mem[i] = 0UL
  }
  for i in 0..<ARGON2_BLOCK_WORDS {
    c[i] = 0UL
    inst.scratch[i] = 0UL
    inst.addr[i] = 0UL
    inst.input[i] = 0UL
  }
  tag
}

///|
/// Argon2id (RFC 9106) with empty secret and associated data: the exact
/// invocation RFC 9580 §3.7.1.4 prescribes for S2K specifier type 4.
///
/// `m_kib` is in kibibytes (not octets) and must be at least
/// `8 * parallelism`. `max_memory_kib` lets a caller parsing untrusted
/// packets enforce a tighter policy than the 2 GiB hard ceiling.
///
/// # Example
/// ```mbt check
/// test {
///   let tag = @primitives.argon2id(b"password", b"somesalt", 1, 64, 1, 24)
///   inspect(
///     @primitives.to_hex(tag),
///     content="655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
///   )
/// }
/// ```
pub fn argon2id(
  pass : BytesView,
  salt : BytesView,
  passes : Int32,
  m_kib : Int32,
  parallelism : Int32,
  tag_len : Int32,
  max_memory_kib~ : Int32 = ARGON2_MAX_MEMORY_KIB,
) -> Bytes raise {
  argon2id_with_secret_ad(
    pass,
    salt,
    Bytes::new(0),
    Bytes::new(0),
    passes,
    m_kib,
    parallelism,
    tag_len,
    max_memory_kib~,
  )
}
