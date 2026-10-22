///|
/// RFC 9580 §5.13.2 Version 2 Symmetrically Encrypted and Integrity
/// Protected Data packet: an AEAD payload split into chunks whose message
/// key and nonce are derived from the session key and a 32-octet salt.
///
/// This differs from the 4880bis tag-20 layer in `aead.mbt` in three ways:
///
/// * the packet tag octet is 0xD2 (tag 18, not tag 20);
/// * the per-chunk associated data is only the 5-octet header (no chunk
///   index), and the final tag's AD appends the total plaintext length;
/// * the nonce is `HKDF-derived IV || u64be(chunk index)` (concatenation,
///   not an XOR into the packet IV).

///|
/// Derive the message key and the fixed part of the AEAD nonce for a v2
/// SEIPD (RFC 9580 §5.13.2): HKDF-SHA256 with the session key as IKM, the
/// packet salt as salt, and `0xD2 | version | cipher | aead | chunk` (the
/// packet header, `header5`) as info. The leftmost `key_len` octets are the
/// message key; the remaining `mode.iv_length() - 8` are the nonce prefix,
/// whose low 64 bits carry the chunk index.
pub fn seipd_v2_kdf(
  session_key : BytesView,
  salt : BytesView,
  key_len : Int32,
  mode : AeadMode,
  header5 : BytesView,
) -> (Bytes, Bytes) raise {
  guard salt.length() == 32 else {
    @error.fail("seipd_v2: the salt must be 32 octets")
  }
  guard header5.length() == 5 else {
    @error.fail("seipd_v2: the header must be 5 octets")
  }
  let iv_len = mode.iv_length()
  guard iv_len >= 8 else { @error.fail("seipd_v2: AEAD nonce shorter than 8") }
  let want = key_len + iv_len - 8
  let okm = @primitives.hkdf_sha256(session_key, salt, header5, want)
  (okm[0:key_len].to_owned(), okm[key_len:want].to_owned())
}

///|
/// The v2 chunk nonce: `iv || u64be(index)`.
fn seipd_v2_nonce(iv : BytesView, index : Int64) -> Bytes raise {
  guard iv.length() + 8 <= 16 + 8 else {
    @error.fail("seipd_v2: bad nonce prefix length")
  }
  let out : Array[Byte] = Array(capacity=iv.length() + 8)
  for b in iv {
    out.push(b)
  }
  for i in 0..<8 {
    let shift = (7 - i) * 8
    out.push(((index >> shift) & 0xFFL).to_int().to_byte())
  }
  Bytes::from_array(out)
}

///|
/// `header5 || u64be(total)` — the final tag's associated data.
fn seipd_v2_final_ad(header5 : BytesView, total : Int64) -> Bytes {
  let out : Array[Byte] = Array(capacity=13)
  for b in header5 {
    out.push(b)
  }
  for i in 0..<8 {
    let shift = (7 - i) * 8
    out.push(((total >> shift) & 0xFFL).to_int().to_byte())
  }
  Bytes::from_array(out)
}

///|
/// Seal a v2 SEIPD payload. `header5` is
/// `0xD2 | 0x02 | cipher | aead | chunk-octet`; `iv` is the HKDF nonce
/// prefix (`mode.iv_length() - 8` octets). Returns the packet tail: chunk
/// ciphertexts+tags followed by the final tag.
pub fn seipd_v2_seal(
  bc : &@primitives.BlockCipher,
  mode : AeadMode,
  header5 : BytesView,
  iv : BytesView,
  chunk_octet : Int32,
  plain : BytesView,
) -> Bytes raise {
  guard header5.length() == 5 else {
    @error.fail("seipd_v2: the header must be 5 octets")
  }
  guard iv.length() == mode.iv_length() - 8 else {
    @error.fail("seipd_v2: bad nonce prefix length")
  }
  // RFC 9580 §5.13.2: implementations MUST NOT create a chunk octet above
  // 16 (4 MiB chunks), though they must accept 0..16 when reading.
  guard chunk_octet >= 0 && chunk_octet <= 16 else {
    @error.fail("seipd_v2: chunk size octet \{chunk_octet} above the 16 limit")
  }
  let chunk_size = aead_chunk_size(chunk_octet)
  let out = Buffer(size_hint=plain.length() + 32)
  let mut index : Int64 = 0L
  let mut off = 0
  while off < plain.length() || index == 0L {
    let remaining = plain.length() - off
    let want = if remaining.to_int64() < chunk_size {
      remaining
    } else {
      chunk_size.to_int()
    }
    let nonce = seipd_v2_nonce(iv, index)
    let chunk_ct = match mode {
      Ocb => ocb_encrypt(bc, nonce.exact_view(), header5, plain[off:off + want])
      Gcm => gcm_encrypt(bc, nonce.exact_view(), header5, plain[off:off + want])
      Eax => eax_encrypt(bc, nonce.exact_view(), header5, plain[off:off + want])
    }
    out.write_bytes(chunk_ct.exact_view())
    off = off + want
    index = index + 1L
  }
  let final_ad = seipd_v2_final_ad(header5, plain.length().to_int64())
  let final_nonce = seipd_v2_nonce(iv, index)
  let tag = match mode {
    Ocb => ocb_encrypt(bc, final_nonce.exact_view(), final_ad.exact_view(), b"")
    Gcm => gcm_encrypt(bc, final_nonce.exact_view(), final_ad.exact_view(), b"")
    Eax => eax_encrypt(bc, final_nonce.exact_view(), final_ad.exact_view(), b"")
  }
  out.write_bytes(tag.exact_view())
  out.to_bytes()
}

///|
/// Open a v2 SEIPD payload (the inverse of `seipd_v2_seal`). Every chunk
/// tag and the final tag must verify.
pub fn seipd_v2_open(
  bc : &@primitives.BlockCipher,
  mode : AeadMode,
  header5 : BytesView,
  iv : BytesView,
  chunk_octet : Int32,
  cipher : BytesView,
) -> Bytes raise {
  guard header5.length() == 5 else {
    @error.fail("seipd_v2: the header must be 5 octets")
  }
  guard iv.length() == mode.iv_length() - 8 else {
    @error.fail("seipd_v2: bad nonce prefix length")
  }
  // RFC 9580 §5.13.2: values 0..16 MUST be accepted.
  guard chunk_octet >= 0 && chunk_octet <= 16 else {
    @error.fail("seipd_v2: chunk size octet \{chunk_octet} out of range")
  }
  guard cipher.length() >= mode.tag_length() else {
    @error.fail("seipd_v2: payload shorter than the final tag")
  }
  let chunk_size = aead_chunk_size(chunk_octet)
  let out = Buffer(size_hint=cipher.length())
  let mut index : Int64 = 0L
  let mut pos = 0
  while cipher.length() - pos > mode.tag_length() {
    let remaining = cipher.length() - pos
    // Reserve this chunk's tag and the final tag.
    let available = remaining - mode.tag_length() - mode.tag_length()
    let want = if available <= 0 {
      0
    } else if available.to_int64() < chunk_size {
      available
    } else {
      chunk_size.to_int()
    }
    let nonce = seipd_v2_nonce(iv, index)
    let opened = match mode {
      Ocb =>
        ocb_decrypt(
          bc,
          nonce.exact_view(),
          header5,
          cipher[pos:pos + want + mode.tag_length()],
        )
      Gcm =>
        gcm_decrypt(
          bc,
          nonce.exact_view(),
          header5,
          cipher[pos:pos + want + mode.tag_length()],
        )
      Eax =>
        eax_decrypt(
          bc,
          nonce.exact_view(),
          header5,
          cipher[pos:pos + want + mode.tag_length()],
        )
    }
    out.write_bytes(opened.exact_view())
    pos = pos + want + mode.tag_length()
    index = index + 1L
  }
  let total : Int64 = out.to_bytes().length().to_int64()
  let final_ad = seipd_v2_final_ad(header5, total)
  let final_nonce = seipd_v2_nonce(iv, index)
  let opened = match mode {
    Ocb =>
      ocb_decrypt(
        bc,
        final_nonce.exact_view(),
        final_ad.exact_view(),
        cipher[pos:cipher.length()],
      )
    Gcm =>
      gcm_decrypt(
        bc,
        final_nonce.exact_view(),
        final_ad.exact_view(),
        cipher[pos:cipher.length()],
      )
    Eax =>
      eax_decrypt(
        bc,
        final_nonce.exact_view(),
        final_ad.exact_view(),
        cipher[pos:cipher.length()],
      )
  }
  guard opened.length() == 0 else {
    @error.fail("seipd_v2: the final tag covers a non-empty plaintext")
  }
  out.to_bytes()
}
