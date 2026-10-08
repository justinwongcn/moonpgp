///|
/// GCM (NIST SP 800-38D) authenticated encryption over a 128-bit block
/// cipher, restricted to the 12-octet IV that RFC 9580 §5.13.5 requires
/// for OpenPGP (the general 1..2^64-bit IV derivation via GHASH is not
/// implemented; a 96-bit IV uses J0 = IV || 0^31 || 1).
///
/// Verified against the published GCM test cases in src/cipher/gcm_test.mbt
/// (AES-128 and AES-256, with and without associated data).

///|
/// GHASH multiplication X · H in GF(2^128) with the GCM bit order
/// (SP 800-38D §6.3): V starts as H, the bits of X select, and the V
/// shift propagates carries from the least- to the most-significant byte,
/// reducing with R = 0xE1 on the bit that falls off.
fn gcm_mul(x : BytesView, h : BytesView) -> Bytes {
  let z = Array::make(16, b'\x00')
  let v = Array::make(16, b'\x00')
  for i in 0..<16 {
    v[i] = h[i]
  }
  for i in 0..<128 {
    if ((x[i / 8].to_int() >> (7 - i % 8)) & 1) == 1 {
      for j in 0..<16 {
        z[j] = (z[j].to_int() ^ v[j].to_int()).to_byte()
      }
    }
    let lsb = v[15].to_int() & 1
    let mut carry = 0
    for j in 0..<16 {
      let hi = v[j].to_int()
      v[j] = (((hi >> 1) | (carry << 7)) & 0xFF).to_byte()
      carry = hi & 1
    }
    if lsb == 1 {
      v[0] = (v[0].to_int() ^ 0xE1).to_byte()
    }
  }
  Bytes::from_array(z)
}

///|
/// GHASH_H(A', C'): both inputs zero-padded to blocks, followed by the
/// 64-bit big-endian bit lengths of A and C (SP 800-38D §6.4).
fn gcm_ghash(h : BytesView, ad : BytesView, ct : BytesView) -> Bytes raise {
  let mut y = Bytes::make(16, b'\x00')
  let mut off = 0
  while off < ad.length() {
    let end = if off + 16 < ad.length() { off + 16 } else { ad.length() }
    let blk : Array[Byte] = Array(capacity=16)
    for i in off..<end {
      blk.push(ad[i])
    }
    while blk.length() < 16 {
      blk.push(b'\x00')
    }
    y = gcm_mul(
      @primitives.xor_bytes(y.exact_view(), Bytes::from_array(blk).exact_view()),
      h,
    )
    off = off + 16
  }
  off = 0
  while off < ct.length() {
    let end = if off + 16 < ct.length() { off + 16 } else { ct.length() }
    let blk : Array[Byte] = Array(capacity=16)
    for i in off..<end {
      blk.push(ct[i])
    }
    while blk.length() < 16 {
      blk.push(b'\x00')
    }
    y = gcm_mul(
      @primitives.xor_bytes(y.exact_view(), Bytes::from_array(blk).exact_view()),
      h,
    )
    off = off + 16
  }
  // The two 64-bit big-endian bit lengths. Int is 32 bits on this
  // toolchain (a 56-bit shift wraps), so the lengths are Int64.
  let lens : Array[Byte] = Array(capacity=16)
  let ad_bits : Int64 = ad.length().to_int64() * 8L
  let ct_bits : Int64 = ct.length().to_int64() * 8L
  for i in 0..<8 {
    let shift = (7 - i) * 8
    lens.push(((ad_bits >> shift) & 0xFFL).to_int().to_byte())
  }
  for i in 0..<8 {
    let shift = (7 - i) * 8
    lens.push(((ct_bits >> shift) & 0xFFL).to_int().to_byte())
  }
  gcm_mul(
    @primitives.xor_bytes(y.exact_view(), Bytes::from_array(lens).exact_view()),
    h,
  )
}

///|
/// J0 = IV || 0^31 || 1 for a 12-octet IV.
fn gcm_j0(iv : BytesView) -> Bytes raise {
  guard iv.length() == 12 else {
    @error.fail("gcm: only a 12-octet IV is supported, got \{iv.length()}")
  }
  let out : Array[Byte] = Array(capacity=16)
  for b in iv {
    out.push(b)
  }
  out.push(b'\x00')
  out.push(b'\x00')
  out.push(b'\x00')
  out.push(b'\x01')
  Bytes::from_array(out)
}

///|
/// Increment the low 32 bits of the counter block (big-endian, mod 2^32).
fn gcm_inc32(ctr : BytesView) -> Bytes {
  let out : Array[Byte] = Array(capacity=16)
  for b in ctr {
    out.push(b)
  }
  // 32-bit counter arithmetic needs Int64: Int is 32 bits on this toolchain.
  let mut v : Int64 = 0L
  for i in 12..<16 {
    v = (v << 8) | ctr[i].to_int().to_int64()
  }
  v = (v + 1L) & 0xFFFFFFFFL
  for i in 12..<16 {
    let shift = (15 - i) * 8
    out[i] = ((v >> shift) & 0xFFL).to_int().to_byte()
  }
  Bytes::from_array(out)
}

///|
/// GCM-ENCRYPT (SP 800-38D §7.1). Returns ciphertext || 16-octet tag.
pub fn gcm_encrypt(
  bc : &@primitives.BlockCipher,
  iv : BytesView,
  ad : BytesView,
  plain : BytesView,
) -> Bytes raise {
  guard bc.block_size() == 16 else {
    @error.fail("gcm: needs a 128-bit block cipher")
  }
  let h = bc.encrypt_block(Bytes::make(16, b'\x00').exact_view())
  let j0 = gcm_j0(iv)
  let out = Buffer(size_hint=plain.length() + 16)
  let mut ctr = gcm_inc32(j0.exact_view())
  let mut off = 0
  while off < plain.length() {
    let end = if off + 16 < plain.length() { off + 16 } else { plain.length() }
    let ks = bc.encrypt_block(ctr.exact_view())
    out.write_bytes(
      @primitives.xor_bytes(plain[off:end], ks.exact_view()[0:end - off]).exact_view(),
    )
    ctr = gcm_inc32(ctr.exact_view())
    off = off + 16
  }
  let ct = out.to_bytes()
  let tag = @primitives.xor_bytes(
    bc.encrypt_block(j0.exact_view()).exact_view(),
    gcm_ghash(h.exact_view(), ad, ct.exact_view()).exact_view(),
  )
  ct.add(tag)
}

///|
/// GCM-DECRYPT (SP 800-38D §7.2). `cipher` is ciphertext || 16-octet tag;
/// raises when the tag does not verify, and only then is no plaintext
/// returned.
pub fn gcm_decrypt(
  bc : &@primitives.BlockCipher,
  iv : BytesView,
  ad : BytesView,
  cipher : BytesView,
) -> Bytes raise {
  guard bc.block_size() == 16 else {
    @error.fail("gcm: needs a 128-bit block cipher")
  }
  guard cipher.length() >= 16 else {
    @error.fail("gcm: ciphertext shorter than the tag")
  }
  let ct = cipher[0:cipher.length() - 16]
  let stored_tag = cipher[cipher.length() - 16:cipher.length()]
  let h = bc.encrypt_block(Bytes::make(16, b'\x00').exact_view())
  let j0 = gcm_j0(iv)
  let tag = @primitives.xor_bytes(
    bc.encrypt_block(j0.exact_view()).exact_view(),
    gcm_ghash(h.exact_view(), ad, ct).exact_view(),
  )
  guard @primitives.ct_equal(tag.exact_view(), stored_tag) else {
    @error.fail("gcm: authentication tag mismatch")
  }
  let out = Buffer(size_hint=ct.length())
  let mut ctr = gcm_inc32(j0.exact_view())
  let mut off = 0
  while off < ct.length() {
    let end = if off + 16 < ct.length() { off + 16 } else { ct.length() }
    let ks = bc.encrypt_block(ctr.exact_view())
    out.write_bytes(
      @primitives.xor_bytes(ct[off:end], ks.exact_view()[0:end - off]).exact_view(),
    )
    ctr = gcm_inc32(ctr.exact_view())
    off = off + 16
  }
  out.to_bytes()
}
