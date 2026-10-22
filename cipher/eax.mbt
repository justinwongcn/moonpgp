///|
/// EAX authenticated encryption (Bellare–Rogaway–Wagner) over a 128-bit
/// block cipher, as RFC 9580 §5.13.3 adopts it: 16-octet nonce, 16-octet
/// tag. EAX is `MAY` in RFC 9580 (OCB is the MTI mode) but Appendix A.9
/// makes it a required interop case, and GnuPG can emit it.
///
/// Construction: `N = CMAC(0^128 || nonce)`, `H = CMAC(1^128 || ad)`,
/// ciphertext `= CTR(N, plaintext)`, `tag = N XOR H XOR CMAC(2^128 ||
/// ciphertext)`, where the `t^128` domain block is 16 octets with `t` in
/// the last octet.

///|
/// The CMAC subkey doubling in GF(2^128) (RFC 4493 §2.3): shift the block
/// left one bit and, when the top bit falls off, XOR R_b into the LAST
/// octet. RFC 4493 numbers bits MSB-first, so R_b = 0^120 || 10000111 is
/// the low octet of the big-endian integer, not the high one.
fn cmac_double(b : BytesView) -> Bytes {
  let out : Array[Byte] = Array::make(16, b'\x00')
  let mut carry = 0
  for i in 0..<16 {
    let idx = 15 - i
    let v = b[idx].to_int()
    out[idx] = (((v << 1) | carry) & 0xFF).to_byte()
    carry = (v >> 7) & 1
  }
  if carry == 1 {
    out[15] = (out[15].to_int() ^ 0x87).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// CMAC (RFC 4493) over `msg` with a 128-bit block cipher.
fn cmac(bc : &@primitives.BlockCipher, msg : BytesView) -> Bytes raise {
  guard bc.block_size() == 16 else {
    @error.fail("eax: CMAC needs a 128-bit block cipher")
  }
  let l = bc.encrypt_block(Bytes::make(16, b'\x00'))
  let k1 = cmac_double(l.exact_view())
  let k2 = cmac_double(k1.exact_view())
  // An empty message is one incomplete block (RFC 4493 §2.4).
  let blocks = if msg.length() == 0 { 1 } else { (msg.length() + 15) / 16 }
  let complete = msg.length() > 0 && msg.length() % 16 == 0
  let last = Array::make(16, b'\x00')
  if complete {
    for i in 0..<16 {
      last[i] = msg[(blocks - 1) * 16 + i]
    }
  } else {
    let off = (blocks - 1) * 16
    let rem = msg.length() - off
    for i in 0..<rem {
      last[i] = msg[off + i]
    }
    last[rem] = b'\x80'
  }
  let km = if complete { k1 } else { k2 }
  for i in 0..<16 {
    last[i] = (last[i].to_int() ^ km[i].to_int()).to_byte()
  }
  let mut x = Bytes::make(16, b'\x00')
  for i in 0..<(blocks - 1) {
    x = bc.encrypt_block(
      @primitives.xor_bytes(x.exact_view(), msg[i * 16:(i + 1) * 16]).exact_view(),
    )
  }
  bc.encrypt_block(
    @primitives.xor_bytes(x.exact_view(), Bytes::from_array(last).exact_view()).exact_view(),
  )
}

///|
/// `OMAC^t(M) = CMAC([t]_128 || M)` — the EAX domain-separated MAC.
fn eax_omac(
  bc : &@primitives.BlockCipher,
  domain : Int32,
  data : BytesView,
) -> Bytes raise {
  let prefix = Array::make(16, b'\x00')
  prefix[15] = domain.to_byte()
  cmac(bc, @primitives.concat2(Bytes::from_array(prefix), data).exact_view())
}

///|
/// Big-endian increment of a 16-octet counter block (mod 2^128).
fn eax_ctr_increment(counter : Bytes) -> Bytes {
  let out = Array::from_iter(counter.iter())
  let mut i = 15
  while i >= 0 {
    let v = (out[i].to_int() + 1) & 0xFF
    out[i] = v.to_byte()
    if v != 0 {
      break
    }
    i = i - 1
  }
  Bytes::from_array(out)
}

///|
/// `CTR_K(N, data)`: AES-CTR whose counter blocks start at `N` and
/// increment as a 128-bit big-endian integer.
fn eax_ctr(
  bc : &@primitives.BlockCipher,
  nonce : BytesView,
  data : BytesView,
) -> Bytes raise {
  guard bc.block_size() == 16 else {
    @error.fail("eax: CTR needs a 128-bit block cipher")
  }
  let out : Array[Byte] = Array(capacity=data.length())
  let mut counter = nonce.to_owned()
  let mut off = 0
  while off < data.length() {
    let ks = bc.encrypt_block(counter.exact_view())
    let n = if data.length() - off < 16 { data.length() - off } else { 16 }
    for i in 0..<n {
      out.push((data[off + i].to_int() ^ ks[i].to_int()).to_byte())
    }
    off = off + n
    counter = eax_ctr_increment(counter)
  }
  Bytes::from_array(out)
}

///|
/// EAX encrypt: returns `ciphertext || tag`.
///
/// # Example
/// ```mbt check
/// test {
///   // RFC 9580 §5.13.3 mode/IV/tag sizes.
///   inspect(@cipher.Eax.iv_length(), content="16")
///   inspect(@cipher.Eax.tag_length(), content="16")
/// }
/// ```
pub fn eax_encrypt(
  bc : &@primitives.BlockCipher,
  nonce : BytesView,
  ad : BytesView,
  plain : BytesView,
) -> Bytes raise {
  guard nonce.length() == 16 else {
    @error.fail("eax: nonce must be 16 octets")
  }
  let n = eax_omac(bc, 0, nonce)
  let h = eax_omac(bc, 1, ad)
  let ct = eax_ctr(bc, n.exact_view(), plain)
  let c = eax_omac(bc, 2, ct.exact_view())
  let tag = @primitives.xor_bytes(
    @primitives.xor_bytes(n.exact_view(), h.exact_view()).exact_view(),
    c.exact_view(),
  )
  ct.add(tag)
}

///|
/// EAX decrypt: `cipher` is `ciphertext || tag`; the tag must verify.
pub fn eax_decrypt(
  bc : &@primitives.BlockCipher,
  nonce : BytesView,
  ad : BytesView,
  cipher : BytesView,
) -> Bytes raise {
  guard nonce.length() == 16 else {
    @error.fail("eax: nonce must be 16 octets")
  }
  guard cipher.length() >= 16 else {
    @error.fail("eax: payload shorter than the tag")
  }
  let ct = cipher[0:cipher.length() - 16]
  let tag = cipher[cipher.length() - 16:cipher.length()]
  let n = eax_omac(bc, 0, nonce)
  let h = eax_omac(bc, 1, ad)
  let c = eax_omac(bc, 2, ct)
  let want = @primitives.xor_bytes(
    @primitives.xor_bytes(n.exact_view(), h.exact_view()).exact_view(),
    c.exact_view(),
  )
  guard @primitives.ct_equal(want.exact_view(), tag) else {
    @error.fail("eax: authentication tag mismatch")
  }
  eax_ctr(bc, n.exact_view(), ct)
}
