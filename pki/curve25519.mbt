///|
/// Curve25519 arithmetic on `@bigint` (RFC 7748 / RFC 8032), replacing the
/// `moonbitstack/mooncrypt` adapters. All values here stay in [0, p) with
/// `p = 2^255 - 19`; `BigInt::mod` truncates, so subtractions go through
/// `fe_sub` which normalizes negatives back into range. Field ops are NOT
/// constant time (see project README); the replacement seam is the public
/// surface of `ed25519.mbt` / `x25519.mbt`, unchanged since the mooncrypt
/// days, so an official `x/crypto` implementation drops in by rewriting
/// those two files alone.

///|
priv struct Ed25519Ctx {
  /// Field modulus 2^255 - 19.
  p : BigInt
  /// Twisted Edwards constant d = -121665/121666 mod p.
  d : BigInt
  /// 2d, the constant the unified addition formulas consume.
  d2 : BigInt
  /// Prime order of the base point: 2^252 + 27742317777372353535851937790883648493.
  l : BigInt
  /// Standard base point (x is the even square root, y = 4/5).
  base : EdPoint
  /// 2^((p-1)/4) mod p, the square-root-of-minus-one adjuster.
  sqrt_factor : BigInt
  /// (p+3)/8 = 2^252 - 2, the exponent of the first square-root guess.
  exp_p38 : BigInt
}

///|
/// Extended homogeneous coordinates: x = X/Z, y = Y/Z, x*y = T/Z.
priv struct EdPoint {
  x : BigInt
  y : BigInt
  z : BigInt
  t : BigInt
}

///|
/// Mutable byte array copy of a view (F18): Bytes is immutable, so the
/// byte-level fixups below (masking, sign-bit edits) go through a scratch
/// Array[Byte] built in one allocation.
fn to_byte_array(view : BytesView) -> Array[Byte] {
  let out : Array[Byte] = Array(capacity=view.length())
  for b in view {
    out.push(b)
  }
  out
}

///|
fn c25519_p() -> BigInt {
  BigInt::from_int(1).shl(255).sub(BigInt::from_int(19))
}

///|
fn fe_add(a : BigInt, b : BigInt, p : BigInt) -> BigInt {
  a.add(b).mod(p)
}

///|
/// `a - b` for a, b in [0, p): one conditional add brings the truncated
/// remainder of `BigInt::mod` back into [0, p).
fn fe_sub(a : BigInt, b : BigInt, p : BigInt) -> BigInt {
  let r = a.sub(b)
  if r < BigInt::from_int(0) {
    r.add(p)
  } else {
    r
  }
}

///|
fn fe_mul(a : BigInt, b : BigInt, p : BigInt) -> BigInt {
  a.mul(b).mod(p)
}

///|
fn fe_sq(a : BigInt, p : BigInt) -> BigInt {
  a.mul(a).mod(p)
}

///|
fn ed_identity() -> EdPoint {
  EdPoint::{
    x: BigInt::from_int(0),
    y: BigInt::from_int(1),
    z: BigInt::from_int(1),
    t: BigInt::from_int(0),
  }
}

///|
/// Unified addition (RFC 8032 §5.1.4); also correct on equal points and
/// the identity, so `ed_scalar_mult` needs no special cases.
fn ed_add(p1 : EdPoint, p2 : EdPoint, ctx : Ed25519Ctx) -> EdPoint {
  let p = ctx.p
  let a = fe_mul(fe_sub(p1.y, p1.x, p), fe_sub(p2.y, p2.x, p), p)
  let b = fe_mul(fe_add(p1.y, p1.x, p), fe_add(p2.y, p2.x, p), p)
  let c = fe_mul(ctx.d2, fe_mul(p1.t, p2.t, p), p)
  let d = fe_add(fe_mul(p1.z, p2.z, p), fe_mul(p1.z, p2.z, p), p)
  let e = fe_sub(b, a, p)
  let f = fe_sub(d, c, p)
  let g = fe_add(d, c, p)
  let h = fe_add(b, a, p)
  EdPoint::{
    x: fe_mul(e, f, p),
    y: fe_mul(g, h, p),
    z: fe_mul(f, g, p),
    t: fe_mul(e, h, p),
  }
}

///|
/// Doubling (RFC 8032 §5.1.4).
fn ed_double(p1 : EdPoint, ctx : Ed25519Ctx) -> EdPoint {
  let p = ctx.p
  let a = fe_sq(p1.x, p)
  let b = fe_sq(p1.y, p)
  let c = fe_add(fe_sq(p1.z, p), fe_sq(p1.z, p), p)
  let h = fe_add(a, b, p)
  let e = fe_sub(h, fe_sq(fe_add(p1.x, p1.y, p), p), p)
  let g = fe_sub(a, b, p)
  let f = fe_add(c, g, p)
  EdPoint::{
    x: fe_mul(e, f, p),
    y: fe_mul(g, h, p),
    z: fe_mul(f, g, p),
    t: fe_mul(e, h, p),
  }
}

///|
/// MSB-first double-and-add over the full `k` bit length.
fn ed_scalar_mult(k : BigInt, pt : EdPoint, ctx : Ed25519Ctx) -> EdPoint {
  let mut r = ed_identity()
  let two = BigInt::from_int(2)
  let bits = k.bit_length()
  for t in 0..<bits {
    let i = bits - 1 - t
    r = ed_double(r, ctx)
    if k.shr(i).mod(two).equal_int(1) {
      r = ed_add(r, pt, ctx)
    }
  }
  r
}

///|
/// Affine (x, y); the identity normalizes to (0, 1).
fn ed_affine(pt : EdPoint, ctx : Ed25519Ctx) -> (BigInt, BigInt) raise {
  if pt.z.is_zero() {
    (BigInt::from_int(0), BigInt::from_int(1))
  } else {
    let zi = mod_inverse(pt.z, ctx.p)
    (fe_mul(pt.x, zi, ctx.p), fe_mul(pt.y, zi, ctx.p))
  }
}

///|
fn ed_equal(p1 : EdPoint, p2 : EdPoint, ctx : Ed25519Ctx) -> Bool raise {
  let (x1, y1) = ed_affine(p1, ctx)
  let (x2, y2) = ed_affine(p2, ctx)
  x1.equal(x2) && y1.equal(y2)
}

///|
/// RFC 8032 §5.1.3 point recovery: x² = (y²-1)/(d·y²+1), square root via
/// the (p+3)/8 exponent, the 2^((p-1)/4) adjuster for the -u branch, and
/// the canonical-sign fixups. Raises on a non-decodable encoding.
fn ed_recover_x(
  y : BigInt,
  sign : Int32,
  p : BigInt,
  d : BigInt,
  sqrt_factor : BigInt,
  exp_p38 : BigInt,
) -> BigInt raise {
  let y2 = fe_sq(y, p)
  let u = fe_sub(y2, BigInt::from_int(1), p)
  let v = fe_add(fe_mul(d, y2, p), BigInt::from_int(1), p)
  let mut x = fe_mul(u, mod_inverse(v, p), p).pow(exp_p38, modulus=p)
  let vx2 = fe_mul(v, fe_sq(x, p), p)
  if !vx2.equal(u) {
    guard vx2.equal(p.sub(u)) else {
      @error.fail("pki: invalid Ed25519 point encoding")
    }
    x = fe_mul(x, sqrt_factor, p)
    guard fe_mul(v, fe_sq(x, p), p).equal(u) else {
      @error.fail("pki: invalid Ed25519 point encoding")
    }
  }
  if x.equal_int(0) && sign == 1 {
    @error.fail("pki: invalid Ed25519 point encoding")
  }
  // The sign bit is the parity of x: negate the recovered root whenever
  // its parity disagrees (RFC 8032 Appendix A recover_x). The raw square
  // root can come out in either parity, so this is not the same as
  // "negate iff sign is 1".
  if x.mod(BigInt::from_int(2)).equal_int(1) != (sign == 1) {
    x = p.sub(x)
  }
  x
}

///|
/// Compressed encoding: 255-bit y little-endian, bit 255 = low bit of x.
fn ed_encode(pt : EdPoint, ctx : Ed25519Ctx) -> Bytes raise {
  let (x, y) = ed_affine(pt, ctx)
  let le = bigint_to_le_bytes(y, 32)
  let out = to_byte_array(le)
  if x.mod(BigInt::from_int(2)).equal_int(1) {
    out[31] = (out[31].to_int() | 0x80).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Inverse of `ed_encode` (RFC 8032 §5.1.3, including the canonical-y and
/// on-curve checks). Raises on any malformed encoding.
fn ed_decode(enc : BytesView, ctx : Ed25519Ctx) -> EdPoint raise {
  guard enc.length() == 32 else {
    @error.malformed("pki: Ed25519 point must be 32 octets")
  }
  let sign = (enc[31].to_int() >> 7) & 1
  let arr = to_byte_array(enc)
  arr[31] = (arr[31].to_int() & 0x7f).to_byte()
  let y = le_bytes_to_bigint(Bytes::from_array(arr).exact_view())
  guard y < ctx.p else { @error.fail("pki: non-canonical Ed25519 point y") }
  let x = ed_recover_x(y, sign, ctx.p, ctx.d, ctx.sqrt_factor, ctx.exp_p38)
  let x2 = fe_sq(x, ctx.p)
  let lhs = fe_sub(fe_sq(y, ctx.p), x2, ctx.p)
  let rhs = fe_add(
    BigInt::from_int(1),
    fe_mul(ctx.d, fe_mul(x2, fe_sq(y, ctx.p), ctx.p), ctx.p),
    ctx.p,
  )
  guard lhs.equal(rhs) else {
    @error.malformed("pki: Ed25519 point not on curve")
  }
  EdPoint::{ x, y, z: BigInt::from_int(1), t: fe_mul(x, y, ctx.p), }
}

///|
fn ed_decode_opt(enc : BytesView, ctx : Ed25519Ctx) -> EdPoint? {
  Some(ed_decode(enc, ctx)) catch {
    _ => None
  }
}

///|
/// SHA-512 of the seed, clamped into the secret scalar a (RFC 8032
/// §5.1.5: clear bits 0-2, clear bit 255, set bit 254), plus the nonce
/// prefix h[32..64].
fn ed_expand_seed(seed : BytesView) -> (BigInt, Bytes) raise {
  guard seed.length() == 32 else {
    @error.malformed("pki: Ed25519 seed must be 32 octets")
  }
  let h = @primitives.Sha512.digest(seed)
  let arr = to_byte_array(h[0:32])
  arr[0] = (arr[0].to_int() & 248).to_byte()
  arr[31] = ((arr[31].to_int() & 127) | 64).to_byte()
  let a = le_bytes_to_bigint(Bytes::from_array(arr).exact_view())
  (a, h[32:64].to_owned())
}

///|
fn ed25519_ctx() -> Ed25519Ctx raise {
  let p = c25519_p()
  let d = p.sub(
    BigInt::from_int(121665)
    .mul(mod_inverse(BigInt::from_int(121666), p))
    .mod(p),
  )
  let d2 = d.mul(BigInt::from_int(2)).mod(p)
  // L = 2^252 + 27742317777372353535851937790883648493, big-endian octets.
  let l = BigInt::from_octets(
    Bytes::from_array([
      0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12,
      0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
    ]).exact_view(),
    signum=1,
  )
  let sqrt_factor = BigInt::from_int(2).pow(
    BigInt::from_int(1).shl(253).sub(BigInt::from_int(5)),
    modulus=p,
  )
  let exp_p38 = BigInt::from_int(1).shl(252).sub(BigInt::from_int(2))
  let by = BigInt::from_int(4).mul(mod_inverse(BigInt::from_int(5), p)).mod(p)
  let bx = ed_recover_x(by, 0, p, d, sqrt_factor, exp_p38)
  Ed25519Ctx::{
    p,
    d,
    d2,
    l,
    base: EdPoint::{
      x: bx,
      y: by,
      z: BigInt::from_int(1),
      t: fe_mul(bx, by, p),
    },
    sqrt_factor,
    exp_p38,
  }
}

///|
/// Little-endian fixed-width encoding of a non-negative BigInt below
/// 2^(8·len). All call sites hold that invariant by construction; the
/// guard turns a future violation into a loud failure instead of
/// silently dropping high bytes.
fn bigint_to_le_bytes(v0 : BigInt, len : Int32) -> Bytes {
  guard v0.bit_length() <= 8 * len else {
    abort("curve25519: bigint_to_le_bytes value does not fit")
  }
  let mut v = v0
  let two56 = BigInt::from_int(256)
  let arr : Array[Byte] = []
  for _ in 0..<len {
    arr.push(v.mod(two56).to_int().to_byte())
    v = v.div(two56)
  }
  Bytes::from_array(arr)
}

///|
/// 32-octet little-endian value with bit 255 cleared (the RFC 7748
/// masking rule for scalars and peer points alike).
fn le_mask_bit255(le : BytesView) -> Bytes {
  guard le.length() == 32 else {
    abort("curve25519: le_mask_bit255 expects 32 octets")
  }
  let arr = to_byte_array(le)
  arr[31] = (arr[31].to_int() & 0x7f).to_byte()
  Bytes::from_array(arr)
}

///|
fn le_bytes_to_bigint(le : BytesView) -> BigInt {
  let mut v = BigInt::from_int(0)
  let n = le.length()
  for k in 0..<n {
    let i = n - 1 - k
    v = v.shl(8).lor(BigInt::from_int(le[i].to_int()))
  }
  v
}

///|
/// RFC 7748 §5 Montgomery ladder. Bit 255 of both inputs is masked here;
/// `k_le` must still be clamped by the caller (bits 0-2 clear, bit 254
/// set). Raises on an all-zero output, which is what a low-order peer
/// point produces.
fn mont_ladder(k_le : BytesView, u_le : BytesView, p : BigInt) -> BigInt raise {
  guard u_le.length() == 32 && k_le.length() == 32 else {
    @error.malformed("pki: X25519 input must be 32 octets")
  }
  let x1 = le_bytes_to_bigint(le_mask_bit255(u_le).exact_view()).mod(p)
  let k = le_bytes_to_bigint(le_mask_bit255(k_le).exact_view())
  let a24 = BigInt::from_int(121665)
  let two = BigInt::from_int(2)
  let mut x2 = BigInt::from_int(1)
  let mut z2 = BigInt::from_int(0)
  let mut x3 = x1
  let mut z3 = BigInt::from_int(1)
  let mut swap = false
  for step in 0..<=254 {
    let t = 254 - step
    let kt = k.shr(t).mod(two).equal_int(1)
    if kt {
      swap = !swap
    }
    if swap {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }
    // RFC 7748 re-seeds the flag from k_t after each conditional swap.
    swap = kt
    let a = fe_add(x2, z2, p)
    let aa = fe_sq(a, p)
    let b = fe_sub(x2, z2, p)
    let bb = fe_sq(b, p)
    let e = fe_sub(aa, bb, p)
    let c = fe_add(x3, z3, p)
    let dif = fe_sub(x3, z3, p)
    let da = fe_mul(dif, a, p)
    let cb = fe_mul(c, b, p)
    x3 = fe_sq(fe_add(da, cb, p), p)
    z3 = fe_mul(x1, fe_sq(fe_sub(da, cb, p), p), p)
    x2 = fe_mul(aa, bb, p)
    z2 = fe_mul(e, fe_add(aa, fe_mul(a24, e, p), p), p)
  }
  if swap {
    let tx = x2
    x2 = x3
    x3 = tx
    let tz = z2
    z2 = z3
    z3 = tz
  }
  guard !z2.is_zero() else {
    @error.malformed("pki: X25519 output is all-zero (low-order peer point)")
  }
  fe_mul(x2, mod_inverse(z2, p), p)
}
