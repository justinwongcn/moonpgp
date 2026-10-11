///|
/// Build and encrypt the plaintext of a SEIPD v1 packet (RFC 9580 §5.13.1):
/// random prefix (bs+2 octets) || inner packets || 0xD3 0x14 || SHA-1 MDC,
/// all in one CFB context with an all-zero IV and no resynchronization.
pub fn seipd_v1_encrypt(
  bc : &@primitives.BlockCipher,
  inner : BytesView,
) -> Bytes raise {
  let prefix = random_prefix(bc.block_size())
  let tail = Bytes::from_array([0xD3, 0x14])
  // Single accumulating buffer (F12): the old Bytes::add chain made three
  // full copies of the plaintext (prefix||inner||tail, then +MDC); this
  // makes exactly one intermediate copy for the SHA-1 input.
  let buf = Buffer(size_hint=prefix.length() + inner.length() + 22)
  buf.write_bytes(prefix.exact_view())
  buf.write_bytes(inner)
  buf.write_bytes(tail.exact_view())
  let mdc = @primitives.Sha1.digest(buf.to_bytes().exact_view())
  buf.write_bytes(mdc.exact_view())
  let zeros = Bytes::make(bc.block_size(), b'\x00')
  cfb_encrypt(bc, zeros, buf.to_bytes().exact_view())
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
  // Plaintext minimum: (bs+2)-octet prefix || inner || 0xD3 0x14 ||
  // 20-octet MDC. An 18-octet (AES-shaped) bound would still admit
  // ciphertexts whose inner slice inverts to empty for 64-bit ciphers,
  // so the bound follows the block size.
  guard ciphertext.length() >= bs + 2 + 22 else {
    @error.fail("seipd: ciphertext too short")
  }
  let zeros = Bytes::make(bs, b'\x00')
  let full = cfb_decrypt(bc, zeros, ciphertext)
  let len = full.length()
  let stored_mdc = full[len - 20:len]
  let hashed = full[0:len - 20]
  // The two octets before the MDC must be the 0xD3 0x14 constants.
  guard hashed[len - 22] == b'\xD3' && hashed[len - 21] == b'\x14' else {
    @error.fail("seipd: missing MDC header octets")
  }
  let computed = @primitives.Sha1.digest(hashed.exact_view())
  guard @primitives.ct_equal(computed.exact_view(), stored_mdc.exact_view()) else {
    @error.fail("seipd: MDC mismatch (message modified)")
  }
  // Quick check: the last two prefix octets repeat after them. (The old
  // hardcoded 16-byte-block offsets silently rejected every 8-byte-block
  // cipher — CAST5/3DES — exposed by the M2 gpg legacy fixtures.)
  guard full[bs - 2] == full[bs] && full[bs - 1] == full[bs + 1] else {
    @error.fail("seipd: prefix quick check failed (wrong session key?)")
  }
  hashed[bs + 2:len - 22].to_owned()
}
