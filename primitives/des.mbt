///|
/// DES and TripleDES (FIPS 46-3), self-implemented for OpenPGP symmetric
/// algorithm 2 (TripleDES) — a read-side requirement: RFC 4880 §9.2 makes
/// 3DES a MUST-implement and old GnuPG/PGP output uses it. OpenPGP never
/// *generates* 3DES in this library; the dispatch in `blockcipher.mbt`
/// only routes legacy payloads here. Keying: three independent 8-octet
/// DES keys (24 octets, EDE order k1|k2|k3).
///
/// The algorithm structure follows the reference formulation: block
/// permutations, the 16-round Feistel with expansion/E-switch/P, the
/// PC1/PC2 key schedule with its rotation calendar, and the S-boxes. The
/// fused Feistel box (S-box output pre-permuted through P, the data
/// rotation factored in) is the standard tabulation of that formulation.

///|
/// General block permutation: bit `perm[position]` of `src` (0-based,
/// most-significant-first) becomes bit `width - 1 - position` of the
/// result.
fn des_permute(src : UInt64, perm : Array[Int32], width : Int32) -> UInt64 {
  let mut block = 0UL
  for position in 0..<perm.length() {
    let bit = (src >> perm[position]) & 1UL
    block = block | (bit << (width - 1 - position))
  }
  block
}

///|
fn des_be_u64(view : BytesView) -> UInt64 {
  let mut v = 0UL
  for i in 0..<8 {
    v = (v << 8) | view[i].to_int().to_uint64()
  }
  v
}

///|
fn des_u64_to_be(v : UInt64) -> Bytes {
  v.to_be_bytes()
}

///|
/// 48-bit PC2 output repacked so each 6-bit key chunk sits in one byte
/// (two high bits zero) — this is what lets the Feistel rounds XOR whole
/// 32-bit halves of the subkey against the expanded data.
fn des_unpack(x : UInt64) -> UInt64 {
  (((x >> (6 * 1)) & 0xffUL) << (8 * 0)) |
  (((x >> (6 * 3)) & 0xffUL) << (8 * 1)) |
  (((x >> (6 * 5)) & 0xffUL) << (8 * 2)) |
  (((x >> (6 * 7)) & 0xffUL) << (8 * 3)) |
  (((x >> (6 * 0)) & 0xffUL) << (8 * 4)) |
  (((x >> (6 * 2)) & 0xffUL) << (8 * 5)) |
  (((x >> (6 * 4)) & 0xffUL) << (8 * 6)) |
  (((x >> (6 * 6)) & 0xffUL) << (8 * 7))
}

///|
/// The fused Feistel box: `box[s][t]` is the P-permuted S-box output for
/// S-box `s`, 6-bit input `t`, with the 1-bit data rotation of the round
/// function already folded in (so the round XORs boxes against the
/// *unrotated* half). 32-bit values carried in UInt64.
fn des_feistel_box() -> Array[Array[UInt64]] {
  Array::makei(8, s => {
    let inner = FixedArray::make(64, 0UL)
    for i in 0..<4 {
      for j in 0..<16 {
        let mut f = des_sboxes[s][i * 16 + j].to_uint64() << (4 * (7 - s))
        f = des_permute(f, des_p, 32)
        // Row is the 1st and 6th S-box address bit, column the middle
        // four — expressed over the 8-bit-chunk layout of `des_unpack`.
        let row = (((i & 2) << 4) | (i & 1)).to_uint64()
        let col = (j << 1).to_uint64()
        let t = (row | col).to_int()
        // The rotation was performed in the rounds; here it is folded in.
        f = (f << 1) | (f >> 31)
        inner[t] = f & 0xFFFFFFFFUL
      }
    }
    Array::from_iter(inner.iter())
  })
}

///|
/// One key half through the 16-step 28-bit rotation calendar.
fn des_ks_rotate(half0 : UInt64) -> Array[UInt64] {
  let mut half = half0
  let out : Array[UInt64] = []
  for i in 0..<16 {
    let r = des_rotations[i]
    // 28-bit circular left shift (mask because UInt64 does not truncate
    // the way the reference's uint32 arithmetic does).
    let v = ((half << r) | (half >> (28 - r))) & 0x0FFFFFFFUL
    out.push(v)
    half = v
  }
  out
}

///|
/// Expand one 8-octet DES key into its 16 unpacked round subkeys.
fn des_generate_subkeys(key : BytesView) -> Array[UInt64] raise {
  guard key.length() == 8 else { @error.fail("des: key must be 8 octets") }
  let permuted = des_permute(des_be_u64(key), des_pc1, 56)
  let left = des_ks_rotate((permuted >> 28) & 0x0FFFFFFFUL)
  let right = des_ks_rotate(permuted & 0x0FFFFFFFUL)
  Array::makei(16, i => {
    let pc2_input = (left[i] << 28) | right[i]
    des_unpack(des_permute(pc2_input, des_pc2, 48))
  })
}

///|
/// The 32-bit Feistel function over two half-rounds, per the fused box.
/// All values are 32-bit quantities in UInt64; XOR and shifts need no
/// masks, so only the box outputs are pre-truncated.
fn des_feistel(
  box : Array[Array[UInt64]],
  l : UInt64,
  r : UInt64,
  k0 : UInt64,
  k1 : UInt64,
) -> (UInt64, UInt64) {
  let mut l = l
  let mut r = r
  let mut t = r ^ (k0 >> 32)
  l = l ^
    (
      box[7][t.to_int() & 0x3f] ^
      box[5][(t >> 8).to_int() & 0x3f] ^
      box[3][(t >> 16).to_int() & 0x3f] ^
      box[1][(t >> 24).to_int() & 0x3f]
    )
  t = (((r << 28) | (r >> 4)) & 0xFFFFFFFFUL) ^ (k0 & 0xFFFFFFFFUL)
  l = l ^
    (
      box[6][t.to_int() & 0x3f] ^
      box[4][(t >> 8).to_int() & 0x3f] ^
      box[2][(t >> 16).to_int() & 0x3f] ^
      box[0][(t >> 24).to_int() & 0x3f]
    )
  t = l ^ (k1 >> 32)
  r = r ^
    (
      box[7][t.to_int() & 0x3f] ^
      box[5][(t >> 8).to_int() & 0x3f] ^
      box[3][(t >> 16).to_int() & 0x3f] ^
      box[1][(t >> 24).to_int() & 0x3f]
    )
  t = (((l << 28) | (l >> 4)) & 0xFFFFFFFFUL) ^ (k1 & 0xFFFFFFFFUL)
  r = r ^
    (
      box[6][t.to_int() & 0x3f] ^
      box[4][(t >> 8).to_int() & 0x3f] ^
      box[2][(t >> 16).to_int() & 0x3f] ^
      box[0][(t >> 24).to_int() & 0x3f]
    )
  (l, r)
}

///|
/// DES (and TripleDES) state: expanded subkey sets plus the shared
/// Feistel box, built once per cipher instance.
priv struct DesState {
  box : Array[Array[UInt64]]
  /// One subkey array per DES key (1 for DES, 3 for 3DES), EDE order.
  keys : Array[Array[UInt64]]
}

///|
fn DesState::crypt(self : DesState, src : BytesView, decrypt : Bool) -> Bytes {
  if src.length() != 8 {
    abort("des: block must be 8 octets")
  }
  let b = des_permute(des_be_u64(src), des_ip, 64)
  let mut left = (b >> 32) & 0xFFFFFFFFUL
  let mut right = b & 0xFFFFFFFFUL
  // The rounds operate on 31-rotated halves; undo before the final
  // permutation (the rotation is folded into the box instead).
  left = ((left << 1) | (left >> 31)) & 0xFFFFFFFFUL
  right = ((right << 1) | (right >> 31)) & 0xFFFFFFFFUL
  if decrypt {
    for i in 0..<8 {
      let sub = self.keys[self.keys.length() - 1]
      let (l, r) = des_feistel(
        self.box,
        left,
        right,
        sub[15 - 2 * i],
        sub[15 - (2 * i + 1)],
      )
      left = l
      right = r
    }
    // Middle key with the half-swap convention, then the first key.
    if self.keys.length() == 3 {
      let mid = self.keys[1]
      for i in 0..<8 {
        let (rl, rr) = des_feistel(
          self.box,
          right,
          left,
          mid[2 * i],
          mid[2 * i + 1],
        )
        left = rr
        right = rl
      }
      let first = self.keys[0]
      for i in 0..<8 {
        let (l, r) = des_feistel(
          self.box,
          left,
          right,
          first[15 - 2 * i],
          first[15 - (2 * i + 1)],
        )
        left = l
        right = r
      }
    }
  } else {
    for i in 0..<8 {
      let sub = self.keys[0]
      let (l, r) = des_feistel(
        self.box,
        left,
        right,
        sub[2 * i],
        sub[2 * i + 1],
      )
      left = l
      right = r
    }
    if self.keys.length() == 3 {
      let mid = self.keys[1]
      for i in 0..<8 {
        let (rl, rr) = des_feistel(
          self.box,
          right,
          left,
          mid[15 - 2 * i],
          mid[15 - (2 * i + 1)],
        )
        left = rr
        right = rl
      }
      let last = self.keys[2]
      for i in 0..<8 {
        let (l, r) = des_feistel(
          self.box,
          left,
          right,
          last[2 * i],
          last[2 * i + 1],
        )
        left = l
        right = r
      }
    }
  }
  left = ((left << 31) | (left >> 1)) & 0xFFFFFFFFUL
  right = ((right << 31) | (right >> 1)) & 0xFFFFFFFFUL
  let pre_output = (right << 32) | left
  des_u64_to_be(des_permute(pre_output, des_fp, 64))
}

///|
impl BlockCipher for DesState with fn block_size(_self) -> Int32 {
  8
}

///|
impl BlockCipher for DesState with fn encrypt_block(self, block) -> Bytes {
  self.crypt(block, false)
}

///|
impl BlockCipher for DesState with fn decrypt_block(self, block) -> Bytes {
  self.crypt(block, true)
}

///|
impl BlockCipher for DesState with fn wipe(self) -> Unit {
  for keys in self.keys {
    for i in 0..<keys.length() {
      keys[i] = 0UL
    }
  }
}

///|
/// Construct the TripleDES (EDE, three independent 8-octet keys, 24
/// octets total) block cipher used for OpenPGP algorithm 2.
pub fn new_des_ede3(key : BytesView) -> &BlockCipher raise {
  guard key.length() == 24 else {
    @error.fail("3DES init failed: key must be 24 octets")
  }
  DesState::{
    box: des_feistel_box(),
    keys: [
      des_generate_subkeys(key[0:8]),
      des_generate_subkeys(key[8:16]),
      des_generate_subkeys(key[16:24]),
    ],
  }
}

///|
/// Single DES — exposed for the FIPS known-answer tests only.
pub fn new_des(key : BytesView) -> &BlockCipher raise {
  guard key.length() == 8 else {
    @error.fail("DES init failed: key must be 8 octets")
  }
  DesState::{ box: des_feistel_box(), keys: [des_generate_subkeys(key)], }
}
