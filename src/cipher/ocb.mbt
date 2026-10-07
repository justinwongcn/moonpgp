///|
/// OCB3 (RFC 7253) authenticated encryption over a 128-bit block cipher —
/// the mandatory-to-implement AEAD of RFC 9580 and the only mode GnuPG
/// 2.4.x produces. OpenPGP always uses a 15-octet nonce and a 16-octet
/// tag; this module supports any nonce of 1..15 octets (the RFC's bit
/// string construction) so the unit tests can use the RFC's own vectors.
///
/// Verified against all 13 (N,A,P,C) samples of RFC 7253 Appendix A in
/// src/cipher/ocb_test.mbt.

///|
/// Multiply by x in GF(2^128) with the OCB reduction polynomial
/// (RFC 7253 §4.1 double()).
fn ocb_double(x : BytesView) -> Bytes {
  let out : Array[Byte] = Array(capacity=16)
  let msb = (x[0].to_int() & 0x80) != 0
  for i in 0..<16 {
    let hi = x[i].to_int()
    let next = if i + 1 < 16 { x[i + 1].to_int() } else { 0 }
    out.push((((hi << 1) | (next >> 7)) & 0xFF).to_byte())
  }
  if msb {
    out[15] = (out[15].to_int() ^ 0x87).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Number of trailing zero bits (RFC 7253 ntz).
fn ocb_ntz(n : Int) -> Int {
  let mut v = n
  let mut x = 0
  while (v & 1) == 0 {
    v = v >> 1
    x = x + 1
  }
  x
}

///|
/// L_0 = double(double(E_K(0))), L_k = double(L_{k-1})
/// (RFC 7253 §4.1 key-dependent variables).
fn ocb_l_table(
  bc : &@primitives.BlockCipher,
  max_k : Int,
) -> (Bytes, Bytes, Array[Bytes]) {
  let zero = Bytes::make(16, b'\x00')
  let l_star = bc.encrypt_block(zero.exact_view())
  let l_dollar = ocb_double(l_star.exact_view())
  let table : Array[Bytes] = [ocb_double(l_dollar.exact_view())]
  for k in 1..<=max_k {
    table.push(ocb_double(table[k - 1].exact_view()))
  }
  (l_star, l_dollar, table)
}

///|
/// Build the 128-bit RFC 7253 nonce block from an N of 1..15 octets:
/// num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N.
/// The final octet of N is byte-aligned, so the block is simply a single
/// 0x01 marker at bit 7 + (120 - bitlen(N)) followed by N in place.
fn ocb_nonce_block(nonce : BytesView) -> FixedArray[Byte] raise {
  let n = nonce.length()
  guard n >= 1 && n <= 15 else {
    @error.fail("ocb: nonce must be 1..15 octets, got \{n}")
  }
  let out = FixedArray::make(16, b'\x00')
  let marker_bit = 7 + (120 - n * 8)
  out[marker_bit / 8] = (1 << (7 - marker_bit % 8)).to_byte()
  for i in 0..<n {
    out[16 - n + i] = nonce[i]
  }
  out
}

///|
/// The OCB partial-block domain separator: part || 1 || zeros to 16 octets
/// (RFC 7253's `A_* || 1 || 0...`).
fn ocb_partial_block(part : BytesView) -> Bytes {
  let out : Array[Byte] = Array(capacity=16)
  for i in 0..<part.length() {
    out.push(part[i])
  }
  out.push(b'\x80')
  while out.length() < 16 {
    out.push(b'\x00')
  }
  Bytes::from_array(out)
}

///|
/// Extract a 128-bit window starting at a bit offset (RFC 7253
/// Stretch[1+bottom..128+bottom]).
fn ocb_bit_window(src : BytesView, bit_off : Int) -> Bytes {
  let out : Array[Byte] = Array(capacity=16)
  for i in 0..<16 {
    let hi_off = bit_off / 8 + i
    let shift = bit_off % 8
    let hi = if hi_off < src.length() { src[hi_off].to_int() } else { 0 }
    let lo = if hi_off + 1 < src.length() {
      src[hi_off + 1].to_int()
    } else {
      0
    }
    out.push((((hi << shift) | (lo >> (8 - shift))) & 0xFF).to_byte())
  }
  Bytes::from_array(out)
}

///|
/// OCB-ENCRYPT (RFC 7253 §4.2). Returns ciphertext || tag (tag_len
/// octets, default 16 as OpenPGP requires).
pub fn ocb_encrypt(
  bc : &@primitives.BlockCipher,
  nonce : BytesView,
  ad : BytesView,
  plain : BytesView,
  tag_len? : Int = 16,
) -> Bytes raise {
  guard bc.block_size() == 16 else {
    @error.fail("ocb: needs a 128-bit block cipher")
  }
  guard tag_len == 16 else {
    @error.fail("ocb: only a 16-octet tag is supported")
  }
  let blocks = plain.length() / 16 + ad.length() / 16 + 2
  let (l_star, l_dollar, l) = ocb_l_table(bc, blocks)
  // Nonce-dependent variables.
  let nb = ocb_nonce_block(nonce)
  let bottom = nb[15].to_int() & 0x3F
  let ci = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    ci[i] = nb[i]
  }
  ci[15] = (ci[15].to_int() & 0xC0).to_byte()
  let ktop = bc.encrypt_block(Bytes::from_iter(ci.iter()).exact_view())
  let stretch = ktop.add(
    @primitives.xor_bytes(ktop.exact_view()[0:8], ktop.exact_view()[1:9]),
  )
  let mut offset = ocb_bit_window(stretch.exact_view(), bottom)
  // HASH(K, A) (RFC 7253 §4.1).
  let mut sum = Bytes::make(16, b'\x00')
  let mut hoff = Bytes::make(16, b'\x00')
  let am = ad.length() / 16
  for i in 1..<=am {
    hoff = @primitives.xor_bytes(hoff.exact_view(), l[ocb_ntz(i)].exact_view())
    sum = @primitives.xor_bytes(
      sum.exact_view(),
      bc
      .encrypt_block(
        @primitives.xor_bytes(ad[(i - 1) * 16:i * 16], hoff.exact_view()).exact_view(),
      )
      .exact_view(),
    )
  }
  let a_star = ad[am * 16:ad.length()]
  if a_star.length() > 0 {
    hoff = @primitives.xor_bytes(hoff.exact_view(), l_star.exact_view())
    let pad = ocb_partial_block(a_star)
    sum = @primitives.xor_bytes(
      sum.exact_view(),
      bc
      .encrypt_block(
        @primitives.xor_bytes(pad.exact_view(), hoff.exact_view()).exact_view(),
      )
      .exact_view(),
    )
  }
  // Encrypt the payload.
  let pm = plain.length() / 16
  let p_star = plain[pm * 16:plain.length()]
  let mut checksum = Bytes::make(16, b'\x00')
  let out = Buffer(size_hint=plain.length() + 16)
  for i in 1..<=pm {
    offset = @primitives.xor_bytes(
      offset.exact_view(),
      l[ocb_ntz(i)].exact_view(),
    )
    let pt = plain[(i - 1) * 16:i * 16]
    let ct = @primitives.xor_bytes(
      bc
      .encrypt_block(
        @primitives.xor_bytes(pt, offset.exact_view()).exact_view(),
      )
      .exact_view(),
      offset.exact_view(),
    )
    out.write_bytes(ct.exact_view())
    checksum = @primitives.xor_bytes(checksum.exact_view(), pt)
  }
  if p_star.length() > 0 {
    offset = @primitives.xor_bytes(offset.exact_view(), l_star.exact_view())
    let keystream = bc.encrypt_block(offset.exact_view())
    out.write_bytes(
      @primitives.xor_bytes(p_star, keystream.exact_view()[0:p_star.length()]).exact_view(),
    )
    let pad = ocb_partial_block(p_star)
    checksum = @primitives.xor_bytes(checksum.exact_view(), pad.exact_view())
  }
  let tag = @primitives.xor_bytes(
    bc
    .encrypt_block(
      @primitives.xor_bytes(
        @primitives.xor_bytes(checksum.exact_view(), offset.exact_view()),
        l_dollar.exact_view(),
      ).exact_view(),
    )
    .exact_view(),
    sum.exact_view(),
  )
  out.write_bytes(tag.exact_view())
  out.to_bytes()
}

///|
/// OCB-DECRYPT (RFC 7253 §4.3). `cipher` is ciphertext || 16-octet tag;
/// raises when the tag does not verify, and only then is no plaintext
/// returned.
pub fn ocb_decrypt(
  bc : &@primitives.BlockCipher,
  nonce : BytesView,
  ad : BytesView,
  cipher : BytesView,
) -> Bytes raise {
  guard bc.block_size() == 16 else {
    @error.fail("ocb: needs a 128-bit block cipher")
  }
  guard cipher.length() >= 16 else {
    @error.fail("ocb: ciphertext shorter than the tag")
  }
  let ct = cipher[0:cipher.length() - 16]
  let stored_tag = cipher[cipher.length() - 16:cipher.length()]
  let blocks = ct.length() / 16 + ad.length() / 16 + 2
  let (l_star, l_dollar, l) = ocb_l_table(bc, blocks)
  let nb = ocb_nonce_block(nonce)
  let bottom = nb[15].to_int() & 0x3F
  let ci = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    ci[i] = nb[i]
  }
  ci[15] = (ci[15].to_int() & 0xC0).to_byte()
  let ktop = bc.encrypt_block(Bytes::from_iter(ci.iter()).exact_view())
  let stretch = ktop.add(
    @primitives.xor_bytes(ktop.exact_view()[0:8], ktop.exact_view()[1:9]),
  )
  let mut offset = ocb_bit_window(stretch.exact_view(), bottom)
  let mut sum = Bytes::make(16, b'\x00')
  let mut hoff = Bytes::make(16, b'\x00')
  let am = ad.length() / 16
  for i in 1..<=am {
    hoff = @primitives.xor_bytes(hoff.exact_view(), l[ocb_ntz(i)].exact_view())
    sum = @primitives.xor_bytes(
      sum.exact_view(),
      bc
      .encrypt_block(
        @primitives.xor_bytes(ad[(i - 1) * 16:i * 16], hoff.exact_view()).exact_view(),
      )
      .exact_view(),
    )
  }
  let a_star = ad[am * 16:ad.length()]
  if a_star.length() > 0 {
    hoff = @primitives.xor_bytes(hoff.exact_view(), l_star.exact_view())
    let pad = ocb_partial_block(a_star)
    sum = @primitives.xor_bytes(
      sum.exact_view(),
      bc
      .encrypt_block(
        @primitives.xor_bytes(pad.exact_view(), hoff.exact_view()).exact_view(),
      )
      .exact_view(),
    )
  }
  let cm = ct.length() / 16
  let c_star = ct[cm * 16:ct.length()]
  let mut checksum = Bytes::make(16, b'\x00')
  let out = Buffer(size_hint=ct.length())
  for i in 1..<=cm {
    offset = @primitives.xor_bytes(
      offset.exact_view(),
      l[ocb_ntz(i)].exact_view(),
    )
    let block = ct[(i - 1) * 16:i * 16]
    let pt = @primitives.xor_bytes(
      bc
      .decrypt_block(
        @primitives.xor_bytes(block, offset.exact_view()).exact_view(),
      )
      .exact_view(),
      offset.exact_view(),
    )
    out.write_bytes(pt.exact_view())
    checksum = @primitives.xor_bytes(checksum.exact_view(), pt.exact_view())
  }
  if c_star.length() > 0 {
    offset = @primitives.xor_bytes(offset.exact_view(), l_star.exact_view())
    let keystream = bc.encrypt_block(offset.exact_view())
    let pt = @primitives.xor_bytes(
      c_star,
      keystream.exact_view()[0:c_star.length()],
    )
    out.write_bytes(pt.exact_view())
    let pad = ocb_partial_block(pt.exact_view())
    checksum = @primitives.xor_bytes(checksum.exact_view(), pad.exact_view())
  }
  let tag = @primitives.xor_bytes(
    bc
    .encrypt_block(
      @primitives.xor_bytes(
        @primitives.xor_bytes(checksum.exact_view(), offset.exact_view()),
        l_dollar.exact_view(),
      ).exact_view(),
    )
    .exact_view(),
    sum.exact_view(),
  )
  guard @primitives.ct_equal(tag.exact_view(), stored_tag) else {
    @error.fail("ocb: authentication tag mismatch")
  }
  out.to_bytes()
}
