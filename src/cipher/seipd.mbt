///|
/// Build and encrypt the plaintext of a SEIPD v1 packet (RFC 9580 §5.13.1):
/// random prefix (16+2 octets) || inner packets || 0xD3 0x14 || SHA-1 MDC,
/// all in one CFB context with an all-zero IV and no resynchronization.
pub fn seipd_v1_encrypt(
  bc : &@primitives.BlockCipher,
  inner : BytesView,
) -> Bytes raise {
  let prefix = random_prefix()
  let tail = Bytes::from_array([0xD3, 0x14])
  let hashed = prefix.add(inner.to_owned()).add(tail)
  let mdc = @primitives.Sha1.digest(hashed.view())
  let plaintext = hashed.add(mdc)
  let zeros = Bytes::make(bc.block_size(), b'\x00')
  cfb_encrypt(bc, zeros, plaintext.view())
}

///|
/// Decrypt and integrity-check a SEIPD v1 ciphertext. Returns the inner
/// packet stream (prefix and MDC stripped). Raises when the quick check
/// octets or the MDC do not match.
pub fn seipd_v1_decrypt(
  bc : &@primitives.BlockCipher,
  ciphertext : BytesView,
) -> Bytes raise {
  let bs = bc.block_size()
  guard ciphertext.length() >= bs + 2 + 2 + 20 else {
    raise @error.PgpError::PgpError(msg="seipd: ciphertext too short")
  }
  let zeros = Bytes::make(bs, b'\x00')
  let full = cfb_decrypt(bc, zeros, ciphertext)
  let len = full.length()
  let stored_mdc = full[len - 20:len]
  let hashed = full[0:len - 20]
  // The two octets before the MDC must be the 0xD3 0x14 constants.
  guard hashed[len - 22] == b'\xD3' && hashed[len - 21] == b'\x14' else {
    raise @error.PgpError::PgpError(msg="seipd: missing MDC header octets")
  }
  let computed = @primitives.Sha1.digest(hashed.view())
  guard @primitives.ct_equal(computed.view(), stored_mdc.view()) else {
    raise @error.PgpError::PgpError(
      msg="seipd: MDC mismatch (message modified)",
    )
  }
  // Quick check: prefix[14..16] repeats at [16..18].
  guard full[14] == full[16] && full[15] == full[17] else {
    raise @error.PgpError::PgpError(
      msg="seipd: prefix quick check failed (wrong session key?)",
    )
  }
  hashed[18:len - 22].to_owned()
}
