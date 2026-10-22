///|
/// CAST5 (CAST-128, RFC 2144), self-implemented for OpenPGP symmetric
/// algorithm 3 — a read-side requirement: it was GnuPG's default cipher
/// before AES, so a large share of legacy payloads and passphrase-
/// protected secret keys are wrapped in it. OpenPGP never *generates*
/// CAST5 here; the dispatch in `blockcipher.mbt` only routes legacy
/// payloads. OpenPGP always uses the full 16-octet key (16 rounds).
///
/// 32-bit arithmetic is done on `UInt` (mod 2^32 is natural there); the
/// helpers keep the add/sub/xor/rotate forms of the RFC literal.

///|
fn cast5_rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn cast5_add(a : UInt32, b : UInt32) -> UInt32 {
  (a.to_uint64() + b.to_uint64()).to_uint()
}

///|
fn cast5_sub(a : UInt32, b : UInt32) -> UInt32 {
  (a.to_uint64() - b.to_uint64()).to_uint()
}

///|
/// Overall byte n of a little array of 32-bit words: byte 0 is the most
/// significant byte of word 0 (RFC notation x0..xF, z0..zF).
fn cast5_byte(words : Array[UInt32], n : Int32) -> Int32 {
  ((words[n / 4] >> (24 - 8 * (n % 4))) & 0xFFU).reinterpret_as_int()
}

///|
priv struct Cast5State {
  /// 16 masking subkeys Km (one per round).
  km : Array[UInt32]
  /// 16 rotation subkeys Kr (5 bits used per round).
  kr : Array[UInt32]
}

///|
/// RFC 2144 §2.4 key schedule. The body (z from x, four K, x' from z,
/// four K) repeats four times; the K equations alternate between two
/// patterns each, selected by the round parity.
fn cast5_schedule(key : BytesView) -> Cast5State raise {
  guard key.length() == 16 else { @error.fail("cast5: key must be 16 octets") }
  let mut x : Array[UInt32] = Array::makei(4, i => {
    (key[4 * i].to_int().reinterpret_as_uint() << 24) |
    (key[4 * i + 1].to_int().reinterpret_as_uint() << 16) |
    (key[4 * i + 2].to_int().reinterpret_as_uint() << 8) |
    key[4 * i + 3].to_int().reinterpret_as_uint()
  })
  let km : Array[UInt32] = []
  let kr : Array[UInt32] = []
  for round in 0..<4 {
    // z0z1z2z3 .. zCzDzEzF from x — identical equations on every pass.
    let z : Array[UInt32] = Array::make(4, 0U)
    z[0] = x[0] ^
      cast5_s5[cast5_byte(x, 13)] ^
      cast5_s6[cast5_byte(x, 15)] ^
      cast5_s7[cast5_byte(x, 12)] ^
      cast5_s8[cast5_byte(x, 14)] ^
      cast5_s7[cast5_byte(x, 8)]
    z[1] = x[2] ^
      cast5_s5[cast5_byte(z, 0)] ^
      cast5_s6[cast5_byte(z, 2)] ^
      cast5_s7[cast5_byte(z, 1)] ^
      cast5_s8[cast5_byte(z, 3)] ^
      cast5_s8[cast5_byte(x, 10)]
    z[2] = x[3] ^
      cast5_s5[cast5_byte(z, 7)] ^
      cast5_s6[cast5_byte(z, 6)] ^
      cast5_s7[cast5_byte(z, 5)] ^
      cast5_s8[cast5_byte(z, 4)] ^
      cast5_s5[cast5_byte(x, 9)]
    z[3] = x[1] ^
      cast5_s5[cast5_byte(z, 10)] ^
      cast5_s6[cast5_byte(z, 9)] ^
      cast5_s7[cast5_byte(z, 11)] ^
      cast5_s8[cast5_byte(z, 8)] ^
      cast5_s6[cast5_byte(x, 11)]
    if round % 2 == 0 {
      // K1..K4 pattern.
      km.push(
        cast5_s5[cast5_byte(z, 8)] ^
        cast5_s6[cast5_byte(z, 9)] ^
        cast5_s7[cast5_byte(z, 7)] ^
        cast5_s8[cast5_byte(z, 6)] ^
        cast5_s5[cast5_byte(z, 2)],
      )
      km.push(
        cast5_s5[cast5_byte(z, 10)] ^
        cast5_s6[cast5_byte(z, 11)] ^
        cast5_s7[cast5_byte(z, 5)] ^
        cast5_s8[cast5_byte(z, 4)] ^
        cast5_s6[cast5_byte(z, 6)],
      )
      km.push(
        cast5_s5[cast5_byte(z, 12)] ^
        cast5_s6[cast5_byte(z, 13)] ^
        cast5_s7[cast5_byte(z, 3)] ^
        cast5_s8[cast5_byte(z, 2)] ^
        cast5_s7[cast5_byte(z, 9)],
      )
      km.push(
        cast5_s5[cast5_byte(z, 14)] ^
        cast5_s6[cast5_byte(z, 15)] ^
        cast5_s7[cast5_byte(z, 1)] ^
        cast5_s8[cast5_byte(z, 0)] ^
        cast5_s8[cast5_byte(z, 12)],
      )
    } else {
      // K9..K12 pattern.
      km.push(
        cast5_s5[cast5_byte(z, 3)] ^
        cast5_s6[cast5_byte(z, 2)] ^
        cast5_s7[cast5_byte(z, 12)] ^
        cast5_s8[cast5_byte(z, 13)] ^
        cast5_s5[cast5_byte(z, 9)],
      )
      km.push(
        cast5_s5[cast5_byte(z, 1)] ^
        cast5_s6[cast5_byte(z, 0)] ^
        cast5_s7[cast5_byte(z, 14)] ^
        cast5_s8[cast5_byte(z, 15)] ^
        cast5_s6[cast5_byte(z, 12)],
      )
      km.push(
        cast5_s5[cast5_byte(z, 7)] ^
        cast5_s6[cast5_byte(z, 6)] ^
        cast5_s7[cast5_byte(z, 8)] ^
        cast5_s8[cast5_byte(z, 9)] ^
        cast5_s7[cast5_byte(z, 2)],
      )
      km.push(
        cast5_s5[cast5_byte(z, 5)] ^
        cast5_s6[cast5_byte(z, 4)] ^
        cast5_s7[cast5_byte(z, 10)] ^
        cast5_s8[cast5_byte(z, 11)] ^
        cast5_s8[cast5_byte(z, 6)],
      )
    }
    // x0x1x2x3 .. xCxDxExF from z — identical equations on every pass.
    let nx : Array[UInt32] = Array::make(4, 0U)
    nx[0] = z[2] ^
      cast5_s5[cast5_byte(z, 5)] ^
      cast5_s6[cast5_byte(z, 7)] ^
      cast5_s7[cast5_byte(z, 4)] ^
      cast5_s8[cast5_byte(z, 6)] ^
      cast5_s7[cast5_byte(z, 0)]
    nx[1] = z[0] ^
      cast5_s5[cast5_byte(nx, 0)] ^
      cast5_s6[cast5_byte(nx, 2)] ^
      cast5_s7[cast5_byte(nx, 1)] ^
      cast5_s8[cast5_byte(nx, 3)] ^
      cast5_s8[cast5_byte(z, 2)]
    nx[2] = z[1] ^
      cast5_s5[cast5_byte(nx, 7)] ^
      cast5_s6[cast5_byte(nx, 6)] ^
      cast5_s7[cast5_byte(nx, 5)] ^
      cast5_s8[cast5_byte(nx, 4)] ^
      cast5_s5[cast5_byte(z, 1)]
    nx[3] = z[3] ^
      cast5_s5[cast5_byte(nx, 10)] ^
      cast5_s6[cast5_byte(nx, 9)] ^
      cast5_s7[cast5_byte(nx, 11)] ^
      cast5_s8[cast5_byte(nx, 8)] ^
      cast5_s6[cast5_byte(z, 3)]
    if round % 2 == 0 {
      // K5..K8 pattern.
      km.push(
        cast5_s5[cast5_byte(nx, 3)] ^
        cast5_s6[cast5_byte(nx, 2)] ^
        cast5_s7[cast5_byte(nx, 12)] ^
        cast5_s8[cast5_byte(nx, 13)] ^
        cast5_s5[cast5_byte(nx, 8)],
      )
      km.push(
        cast5_s5[cast5_byte(nx, 1)] ^
        cast5_s6[cast5_byte(nx, 0)] ^
        cast5_s7[cast5_byte(nx, 14)] ^
        cast5_s8[cast5_byte(nx, 15)] ^
        cast5_s6[cast5_byte(nx, 13)],
      )
      km.push(
        cast5_s5[cast5_byte(nx, 7)] ^
        cast5_s6[cast5_byte(nx, 6)] ^
        cast5_s7[cast5_byte(nx, 8)] ^
        cast5_s8[cast5_byte(nx, 9)] ^
        cast5_s7[cast5_byte(nx, 3)],
      )
      km.push(
        cast5_s5[cast5_byte(nx, 5)] ^
        cast5_s6[cast5_byte(nx, 4)] ^
        cast5_s7[cast5_byte(nx, 10)] ^
        cast5_s8[cast5_byte(nx, 11)] ^
        cast5_s8[cast5_byte(nx, 7)],
      )
    } else {
      // K13..K16 pattern.
      km.push(
        cast5_s5[cast5_byte(nx, 8)] ^
        cast5_s6[cast5_byte(nx, 9)] ^
        cast5_s7[cast5_byte(nx, 7)] ^
        cast5_s8[cast5_byte(nx, 6)] ^
        cast5_s5[cast5_byte(nx, 3)],
      )
      km.push(
        cast5_s5[cast5_byte(nx, 10)] ^
        cast5_s6[cast5_byte(nx, 11)] ^
        cast5_s7[cast5_byte(nx, 5)] ^
        cast5_s8[cast5_byte(nx, 4)] ^
        cast5_s6[cast5_byte(nx, 7)],
      )
      km.push(
        cast5_s5[cast5_byte(nx, 12)] ^
        cast5_s6[cast5_byte(nx, 13)] ^
        cast5_s7[cast5_byte(nx, 3)] ^
        cast5_s8[cast5_byte(nx, 2)] ^
        cast5_s7[cast5_byte(nx, 8)],
      )
      km.push(
        cast5_s5[cast5_byte(nx, 14)] ^
        cast5_s6[cast5_byte(nx, 15)] ^
        cast5_s7[cast5_byte(nx, 1)] ^
        cast5_s8[cast5_byte(nx, 0)] ^
        cast5_s8[cast5_byte(nx, 13)],
      )
    }
    x = nx
  }
  // §2.4.1: Kmi = Ki, Kri = K16+i (5 bits).
  for i in 0..<16 {
    kr.push(km[16 + i] & 0x1FU)
  }
  Cast5State::{ km, kr, }
}

///|
/// The three round functions (RFC 2144 §2.2). Ia..Id are the bytes of I,
/// most significant first.
fn cast5_f(state : Cast5State, round : Int32, d : UInt32) -> UInt32 {
  let km = state.km[round]
  let kr = state.kr[round].reinterpret_as_int()
  let i : UInt32 = match round % 3 {
    0 => cast5_rotl(cast5_add(km, d), kr)
    1 => cast5_rotl(km ^ d, kr)
    _ => cast5_rotl(cast5_sub(km, d), kr)
  }
  let ia = (i >> 24).reinterpret_as_int() & 0xFF
  let ib = ((i >> 16) & 0xFFU).reinterpret_as_int()
  let ic = ((i >> 8) & 0xFFU).reinterpret_as_int()
  let id = (i & 0xFFU).reinterpret_as_int()
  match round % 3 {
    // ((cast5_s1 ^ cast5_s2) - cast5_s3) + cast5_s4
    0 =>
      cast5_add(
        cast5_sub(cast5_s1[ia] ^ cast5_s2[ib], cast5_s3[ic]),
        cast5_s4[id],
      )
    // ((cast5_s1 - cast5_s2) + cast5_s3) ^ cast5_s4
    1 =>
      cast5_add(cast5_sub(cast5_s1[ia], cast5_s2[ib]), cast5_s3[ic]) ^
      cast5_s4[id]
    // ((cast5_s1 + cast5_s2) ^ cast5_s3) - cast5_s4
    _ =>
      cast5_sub(
        cast5_add(cast5_s1[ia], cast5_s2[ib]) ^ cast5_s3[ic],
        cast5_s4[id],
      )
  }
}

///|
fn Cast5State::crypt(
  self : Cast5State,
  src : BytesView,
  decrypt : Bool,
) -> Bytes {
  if src.length() != 8 {
    abort("cast5: block must be 8 octets")
  }
  let mut l : UInt32 = (src[0].to_int().reinterpret_as_uint() << 24) |
    (src[1].to_int().reinterpret_as_uint() << 16) |
    (src[2].to_int().reinterpret_as_uint() << 8) |
    src[3].to_int().reinterpret_as_uint()
  let mut r : UInt32 = (src[4].to_int().reinterpret_as_uint() << 24) |
    (src[5].to_int().reinterpret_as_uint() << 16) |
    (src[6].to_int().reinterpret_as_uint() << 8) |
    src[7].to_int().reinterpret_as_uint()
  // Feistel with the half swap; decryption is the same rounds with the
  // subkey order reversed (the ciphertext is loaded as R16||L16, which
  // the wire's first half already is).
  for i in 0..<16 {
    let round = if decrypt { 15 - i } else { i }
    let f = cast5_f(self, round, r)
    let nl = r
    r = l ^ f
    l = nl
  }
  // Ciphertext = R16 || L16.
  let out : Array[Byte] = [
    ((r >> 24) & 0xFFU).to_byte(),
    ((r >> 16) & 0xFFU).to_byte(),
    ((r >> 8) & 0xFFU).to_byte(),
    (r & 0xFFU).to_byte(),
    ((l >> 24) & 0xFFU).to_byte(),
    ((l >> 16) & 0xFFU).to_byte(),
    ((l >> 8) & 0xFFU).to_byte(),
    (l & 0xFFU).to_byte(),
  ]
  Bytes::from_array(out)
}

///|
impl BlockCipher for Cast5State with fn block_size(_self) -> Int32 {
  8
}

///|
impl BlockCipher for Cast5State with fn encrypt_block(self, block) -> Bytes {
  self.crypt(block, false)
}

///|
impl BlockCipher for Cast5State with fn decrypt_block(self, block) -> Bytes {
  self.crypt(block, true)
}

///|
impl BlockCipher for Cast5State with fn wipe(self) -> Unit {
  for i in 0..<self.km.length() {
    self.km[i] = 0U
    self.kr[i] = 0U
  }
}

///|
/// Construct the CAST5 block cipher for OpenPGP algorithm 3 (16-octet
/// key, 16 rounds).
pub fn new_cast5(key : BytesView) -> &BlockCipher raise {
  cast5_schedule(key)
}
