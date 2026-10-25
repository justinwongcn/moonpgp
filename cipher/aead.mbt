///|
/// OpenPGP AEAD framing (draft-ietf-openpgp-rfc4880bis §5.16 / the
/// crypto-refresh §5.16 SEIPD-v2 chunk layer): an AEAD payload is split
/// into chunks of 2^(c+6) octets, each sealed with a per-chunk nonce and
/// associated data, followed by a final tag over the total plaintext
/// length. GnuPG 2.4.x produces exactly this shape for tag-20 packets.
///
/// Per-chunk AD:  0xD4 | version | cipher | aead | chunk-octet | u64(index)
/// Final AD:      0xD4 | version | cipher | aead | chunk-octet |
///                u64(index of the final chunk) | u64(total plaintext octets)
/// Nonce(n):      the packet IV with the u64 chunk index XORed into its
///                last 8 octets.

///|
/// AEAD algorithm IDs (RFC 9580 §9.6).
pub(all) enum AeadMode {
  Eax
  Ocb
  Gcm
} derive(Eq, Debug)

///|
pub extend AeadMode with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend AeadMode with Eq::{not_equal, equal}

///|
pub fn AeadMode::number(self : AeadMode) -> Int32 {
  match self {
    Eax => 1
    Ocb => 2
    Gcm => 3
  }
}

///|
pub fn aead_mode_of_number(n : Int32) -> AeadMode? {
  match n {
    1 => Some(Eax)
    2 => Some(Ocb)
    3 => Some(Gcm)
    _ => None
  }
}

///|
/// IV/nonce length of the mode (RFC 9580 §9.6).
pub fn AeadMode::iv_length(self : AeadMode) -> Int32 {
  match self {
    Eax => 16
    Ocb => 15
    Gcm => 12
  }
}

///|
/// Tag length — 16 octets for every registered mode.
pub fn AeadMode::tag_length(_self : AeadMode) -> Int32 {
  16
}

///|
/// Chunk size for the chunk-size octet: 2^(c + 6) octets. Computed as an
/// Int64 (Int is 32 bits here and the octet can encode up to 2^56);
/// callers clamp it against the remaining payload.
pub fn aead_chunk_size(chunk_octet : Int32) -> Int64 raise {
  guard chunk_octet >= 0 && chunk_octet <= 56 else {
    @error.fail("aead: chunk size octet \{chunk_octet} out of range")
  }
  let shift = chunk_octet + 6
  let mut size : Int64 = 1L
  let mut i = 0
  while i < shift {
    size = size * 2L
    i = i + 1
  }
  size
}

///|
/// Seal one chunk with `mode` under the chunk nonce (IV with the index
/// XORed into the last 8 octets).
fn aead_seal_chunk(
  bc : &@primitives.BlockCipher,
  mode : AeadMode,
  iv : BytesView,
  index : Int64,
  ad : BytesView,
  plain : BytesView,
) -> Bytes raise {
  let nonce = aead_chunk_nonce(iv, index)
  match mode {
    Ocb => ocb_encrypt(bc, nonce.exact_view(), ad, plain)
    Gcm => gcm_encrypt(bc, nonce.exact_view(), ad, plain)
    Eax => eax_encrypt(bc, nonce.exact_view(), ad, plain)
  }
}

///|
/// Open one chunk, raising when the tag does not verify.
fn aead_open_chunk(
  bc : &@primitives.BlockCipher,
  mode : AeadMode,
  iv : BytesView,
  index : Int64,
  ad : BytesView,
  cipher : BytesView,
) -> Bytes raise {
  let nonce = aead_chunk_nonce(iv, index)
  match mode {
    Ocb => ocb_decrypt(bc, nonce.exact_view(), ad, cipher)
    Gcm => gcm_decrypt(bc, nonce.exact_view(), ad, cipher)
    Eax => eax_decrypt(bc, nonce.exact_view(), ad, cipher)
  }
}

///|
/// The per-chunk nonce: the packet IV with the 8-octet big-endian chunk
/// index XORed into its tail. The index is a parameter, NOT read from the
/// AD tail — the final tag's AD ends with the total-octet count.
fn aead_chunk_nonce(iv : BytesView, index : Int64) -> Bytes raise {
  guard iv.length() >= 8 else { @error.fail("aead: IV shorter than 8 octets") }
  let idx : Array[Byte] = Array(capacity=8)
  for i in 0..<8 {
    let shift = (7 - i) * 8
    idx.push(((index >> shift) & 0xFFL).to_int().to_byte())
  }
  let out : Array[Byte] = Array(capacity=iv.length())
  for i in 0..<iv.length() {
    let x = if i + 8 >= iv.length() {
      idx[i + 8 - iv.length()].to_int()
    } else {
      0
    }
    out.push((iv[i].to_int() ^ x).to_byte())
  }
  Bytes::from_array(out)
}

///|
/// Assemble AD bytes: header5 || u64(index) || tail.
fn aead_ad(header5 : BytesView, index : Int64, tail : BytesView) -> Bytes {
  let out : Array[Byte] = Array(capacity=5 + 8 + tail.length())
  for b in header5 {
    out.push(b)
  }
  for i in 0..<8 {
    let shift = (7 - i) * 8
    out.push(((index >> shift) & 0xFFL).to_int().to_byte())
  }
  for b in tail {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// Seal a full AEAD payload (the OpenPGP chunk layer). `header5` is
/// 0xD4 | version | cipher | aead | chunk-octet; `iv` is the packet IV.
/// Returns the packet body tail: chunk ciphertexts+tags followed by the
/// final tag. An empty payload still produces one empty chunk tag plus
/// the final tag (what go-crypto/OpenPGP.js emit).
pub fn aead_seal(
  bc : &@primitives.BlockCipher,
  mode : AeadMode,
  header5 : BytesView,
  iv : BytesView,
  chunk_octet : Int32,
  plain : BytesView,
) -> Bytes raise {
  guard iv.length() == mode.iv_length() else {
    @error.fail("aead: bad IV length for the mode")
  }
  let chunk_size = aead_chunk_size(chunk_octet)
  let out = Buffer(size_hint=plain.length() + 32)
  let mut index : Int64 = 0L
  let mut off = 0
  // At least one chunk is emitted, even for an empty payload.
  while off < plain.length() || index == 0L {
    let remaining = plain.length() - off
    let want = if remaining.to_int64() < chunk_size {
      remaining
    } else {
      chunk_size.to_int()
    }
    let ad = aead_ad(header5, index, Bytes::new(0).exact_view())
    out.write_bytes(
      aead_seal_chunk(
        bc,
        mode,
        iv,
        index,
        ad.exact_view(),
        plain[off:off + want],
      ).exact_view(),
    )
    off = off + want
    index = index + 1L
  }
  // Final tag: empty plaintext, index = number of data chunks, and the
  // total plaintext octet count in the AD tail.
  let total : Array[Byte] = Array(capacity=8)
  let total_i64 : Int64 = plain.length().to_int64()
  for i in 0..<8 {
    let shift = (7 - i) * 8
    total.push(((total_i64 >> shift) & 0xFFL).to_int().to_byte())
  }
  let fad = aead_ad(header5, index, Bytes::from_array(total).exact_view())
  out.write_bytes(
    aead_seal_chunk(
      bc,
      mode,
      iv,
      index,
      fad.exact_view(),
      Bytes::new(0).exact_view(),
    ).exact_view(),
  )
  out.to_bytes()
}

///|
/// Open a full AEAD payload (the inverse of `aead_seal`). The final tag
/// must verify against the total plaintext length; any chunk tag failure
/// raises.
pub fn aead_open(
  bc : &@primitives.BlockCipher,
  mode : AeadMode,
  header5 : BytesView,
  iv : BytesView,
  chunk_octet : Int32,
  cipher : BytesView,
) -> Bytes raise {
  guard iv.length() == mode.iv_length() else {
    @error.fail("aead: bad IV length for the mode")
  }
  guard cipher.length() >= mode.tag_length() else {
    @error.fail("aead: payload shorter than the final tag")
  }
  let chunk_size = aead_chunk_size(chunk_octet)
  let out = Buffer(size_hint=cipher.length())
  let mut index : Int64 = 0L
  let mut pos = 0
  // Data chunks: while more than the final tag remains. Each chunk
  // reserves its own tag AND the final tag, so the last 16 octets are
  // always the final tag (a payload that is an exact chunk multiple has
  // no trailing empty chunk, but an all-empty payload does).
  while cipher.length() - pos > mode.tag_length() {
    let remaining = cipher.length() - pos
    let available = remaining - mode.tag_length() - mode.tag_length()
    let want = if available <= 0 {
      0
    } else if available.to_int64() < chunk_size {
      available
    } else {
      chunk_size.to_int()
    }
    let ad = aead_ad(header5, index, Bytes::new(0).exact_view())
    out.write_bytes(
      aead_open_chunk(
        bc,
        mode,
        iv,
        index,
        ad.exact_view(),
        cipher[pos:pos + want + mode.tag_length()],
      ).exact_view(),
    )
    pos = pos + want + mode.tag_length()
    index = index + 1L
  }
  // Final tag.
  let total : Array[Byte] = Array(capacity=8)
  let total_i64 : Int64 = out.length().to_int64()
  for i in 0..<8 {
    let shift = (7 - i) * 8
    total.push(((total_i64 >> shift) & 0xFFL).to_int().to_byte())
  }
  let fad = aead_ad(header5, index, Bytes::from_array(total).exact_view())
  ignore(
    aead_open_chunk(
      bc,
      mode,
      iv,
      index,
      fad.exact_view(),
      cipher[pos:cipher.length()],
    ),
  )
  out.to_bytes()
}
