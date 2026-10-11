///|
/// Full-block CFB encryption (NIST SP 800-38A CFB128) with a
/// caller-provided IV. The final block may be partial; only the needed
/// keystream octets are consumed.
pub fn cfb_encrypt(
  bc : &@primitives.BlockCipher,
  iv : BytesView,
  data : BytesView,
) -> Bytes raise {
  let bs = bc.block_size()
  guard iv.length() == bs else { @error.fail("cfb: bad IV length") }
  let mut fr = iv.to_owned()
  let out = Buffer(size_hint=data.length())
  let mut off = 0
  while off < data.length() {
    let keystream = bc.encrypt_block(fr.exact_view())
    let end = if off + bs < data.length() { off + bs } else { data.length() }
    let ct = @primitives.xor_bytes(
      data[off:end],
      keystream.exact_view()[0:end - off],
    )
    out.write_bytes(ct.exact_view())
    if end - off == bs {
      fr = ct
    }
    off = end
  }
  out.to_bytes()
}

///|
/// Full-block CFB decryption with a caller-provided IV. The final block
/// may be partial.
pub fn cfb_decrypt(
  bc : &@primitives.BlockCipher,
  iv : BytesView,
  data : BytesView,
) -> Bytes raise {
  let bs = bc.block_size()
  guard iv.length() == bs else { @error.fail("cfb: bad IV length") }
  let mut fr = iv.to_owned()
  let out = Buffer(size_hint=data.length())
  let mut off = 0
  while off < data.length() {
    let keystream = bc.encrypt_block(fr.exact_view())
    let end = if off + bs < data.length() { off + bs } else { data.length() }
    let pt = @primitives.xor_bytes(
      data[off:end],
      keystream.exact_view()[0:end - off],
    )
    out.write_bytes(pt.exact_view())
    if end - off == bs {
      fr = data[off:end].to_owned()
    }
    off = end
  }
  out.to_bytes()
}

///|
/// The random prefix of SEIPD v1 / OpenPGP CFB: `bs` random octets then a
/// copy of the last two (RFC 9580 §5.13.1). `bs` is the block size of the
/// session-key cipher — 16 for AES but 8 for the legacy CAST5/3DES, where
/// the old hardcoded 16 quietly produced an invalid prefix.
pub fn random_prefix(bs : Int) -> Bytes raise {
  let p = @primitives.random_bytes(bs)
  p.add(p[bs - 2:bs].to_owned())
}

///|
/// Encrypt with the legacy OpenPGP CFB variant used by the obsolete
/// Symmetrically Encrypted Data packet (tag 9): the 18-octet prefix is
/// encrypted in one CFB context with an all-zero IV, then the CFB state
/// is resynchronized with the last block-size octets of ciphertext
/// (RFC 9580 §5.7).
pub fn openpgp_cfb_encrypt_resync(
  bc : &@primitives.BlockCipher,
  prefix : BytesView,
  data : BytesView,
) -> Bytes raise {
  let bs = bc.block_size()
  guard prefix.length() == bs + 2 else { @error.fail("cfb: bad prefix length") }
  let zeros = Bytes::make(bs, b'\x00')
  // First block: C0 = P0 XOR E(0).
  let ks0 = bc.encrypt_block(zeros.exact_view())
  let c0 = @primitives.xor_bytes(prefix[0:bs], ks0.exact_view())
  // Check bytes: C[bs..bs+2] = P[bs..bs+2] XOR E(C0)[0..2].
  let ks1 = bc.encrypt_block(c0.exact_view())
  let checks = @primitives.xor_bytes(prefix[bs:bs + 2], ks1.exact_view()[0:2])
  let head = c0.add(checks)
  // Resynchronize: FR = C[2..bs+2].
  let fr = head.exact_view()[2:bs + 2]
  let rest = cfb_encrypt(bc, fr, data)
  head.add(rest)
}

///|
/// Decrypt the resynchronized OpenPGP CFB variant. Verifies the two check
/// octets of the prefix and returns the data (prefix stripped).
pub fn openpgp_cfb_decrypt_resync(
  bc : &@primitives.BlockCipher,
  ciphertext : BytesView,
) -> Bytes raise {
  let bs = bc.block_size()
  guard ciphertext.length() >= bs + 2 else {
    @error.fail("cfb: ciphertext too short")
  }
  let zeros = Bytes::make(bs, b'\x00')
  let ks0 = bc.encrypt_block(zeros.exact_view())
  let p0 = @primitives.xor_bytes(
    ciphertext.exact_view()[0:bs],
    ks0.exact_view(),
  )
  // Check bytes come from E(C0) keystream.
  let ks1 = bc.encrypt_block(ciphertext.exact_view()[0:bs])
  let checks = @primitives.xor_bytes(
    ciphertext.exact_view()[bs:bs + 2],
    ks1.exact_view()[0:2],
  )
  let prefix = p0.add(checks)
  guard prefix[bs - 2] == prefix[bs] && prefix[bs - 1] == prefix[bs + 1] else {
    @error.fail("cipher: CFB quick check failed (wrong session key?)")
  }
  // Resynchronize: FR = C[2..bs+2].
  let fr = ciphertext.exact_view()[2:bs + 2]
  cfb_decrypt(bc, fr, ciphertext.exact_view()[bs + 2:ciphertext.length()])
}
