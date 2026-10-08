///|
/// HKDF-SHA256 (RFC 5869). This exists for RFC 9580 §5.5.3: when secret key
/// material is protected with S2K usage octet 253 (AEAD), the S2K-derived
/// key is stretched through HKDF-SHA256 with an empty salt and the packet's
/// own parameters as the `info` string, so one Argon2/iterated derivation
/// can safely serve key and nonce separation.

///|
/// HKDF-Extract: `PRK = HMAC-SHA256(salt, IKM)`. An empty `salt` is treated
/// as `HashLen` zero octets, which is exactly what HMAC's zero-padding of a
/// short key already produces.
fn hkdf_sha256_extract(ikm : BytesView, salt : BytesView) -> Bytes {
  Sha256.hmac(salt, ikm)
}

///|
/// HKDF-SHA256 (RFC 5869 §2): extract then expand to `out_len` octets.
///
/// # Example
/// ```mbt check
/// test {
///   let ikm = @primitives.from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
///   let okm = @primitives.hkdf_sha256(
///     ikm,
///     @primitives.from_hex("000102030405060708090a0b0c"),
///     @primitives.from_hex("f0f1f2f3f4f5f6f7f8f9"),
///     42,
///   )
///   inspect(
///     @primitives.to_hex(okm),
///     content=(
///       #|3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
///     ),
///   )
/// }
/// ```
pub fn hkdf_sha256(
  ikm : BytesView,
  salt : BytesView,
  info : BytesView,
  out_len : Int,
) -> Bytes raise {
  guard out_len >= 0 && out_len <= 255 * 32 else {
    @error.fail("hkdf: output length must be 0..8160 octets")
  }
  let prk = hkdf_sha256_extract(ikm, salt)
  let out : Array[Byte] = Array(capacity=out_len)
  let mut block = Bytes::new(0)
  let mut counter = 1
  while out.length() < out_len {
    let input = concat3(block, info, Bytes::from_array([counter.to_byte()]))
    block = Sha256.hmac(prk, input)
    for b in block {
      if out.length() < out_len {
        out.push(b)
      }
    }
    counter = counter + 1
  }
  Bytes::from_array(out)
}
