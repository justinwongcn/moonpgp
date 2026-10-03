///|
/// AES Key Wrap (RFC 3394), used as the ECDH session-key wrapping method
/// (RFC 9580 §11.5). Built on the block-cipher trait only, so it works
/// with any backing AES implementation.

///|
let kw_iv : Array[Byte] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]

///|
fn block_cipher_for_key_size(key_len : Int) -> @primitives.CipherAlgo raise {
  match key_len {
    16 => @primitives.Aes128
    24 => @primitives.Aes192
    32 => @primitives.Aes256
    _ =>
      raise @error.PgpError::PgpError(
        msg="cipher: no AES variant for KEK size \{key_len}",
      )
  }
}

///|
/// Wrap `plaintext` (a positive multiple of 8 octets) under `kek`,
/// returning (n+1) 8-octet blocks.
pub fn aes_key_wrap(kek : BytesView, plaintext : BytesView) -> Bytes raise {
  guard plaintext.length() >= 16 && plaintext.length() % 8 == 0 else {
    raise @error.PgpError::PgpError(
      msg="cipher: key-wrap input must be a multiple of 8 octets (got \{plaintext.length()})",
    )
  }
  let bc = @primitives.new_block_cipher(
    block_cipher_for_key_size(kek.length()),
    kek,
  )
  let n = plaintext.length() / 8
  // A starts as the default IV; R[i] = P[i] for all i (RFC 3394 §2.2.1).
  let a : Array[Byte] = Array::make(8, b'\x00')
  for i in 0..<8 {
    a[i] = kw_iv[i]
  }
  // r holds the n data blocks R[i] = P[i]; the output is C0 = A then
  // C[i] = R[i], n+1 blocks total (8 octets more than the input).
  let r : Array[Array[Byte]] = []
  for i in 0..<n {
    let blk : Array[Byte] = Array::make(8, b'\x00')
    for k in 0..<8 {
      blk[k] = plaintext[i * 8 + k]
    }
    r.push(blk)
  }
  for j in 0..<6 {
    for i in 1..<(n + 1) {
      let b : Array[Byte] = Array::make(16, b'\x00')
      for k in 0..<8 {
        b[k] = a[k]
        b[8 + k] = r[i - 1][k]
      }
      let out = bc.encrypt_block(Bytes::from_array(b).exact_view())
      // A = MSB_64(B) XOR t (64-bit big-endian counter, t = n*j + i).
      // t always fits well under 2^32, so only the low four octets can
      // be nonzero; shifts stay below 32 bits.
      let t = n * j + i
      for k in 4..<8 {
        a[k] = (out[k].to_int() ^ ((t >> (8 * (7 - k))) & 0xFF)).to_byte()
      }
      for k in 0..<4 {
        a[k] = out[k]
      }
      for k in 0..<8 {
        r[i - 1][k] = out[8 + k]
      }
    }
  }
  let out : Array[Byte] = []
  for k in 0..<8 {
    out.push(a[k])
  }
  for blk in r {
    for k in 0..<8 {
      out.push(blk[k])
    }
  }
  Bytes::from_array(out)
}

///|
/// Unwrap an RFC 3394 key-wrap ciphertext; raises when the integrity
/// check value (the unwrapped A) does not match the default IV.
pub fn aes_key_unwrap(kek : BytesView, ciphertext : BytesView) -> Bytes raise {
  guard ciphertext.length() >= 24 && ciphertext.length() % 8 == 0 else {
    raise @error.PgpError::PgpError(
      msg="cipher: key-unwrap input must be a multiple of 8 octets (got \{ciphertext.length()})",
    )
  }
  let bc = @primitives.new_block_cipher(
    block_cipher_for_key_size(kek.length()),
    kek,
  )
  let n = ciphertext.length() / 8 - 1
  let a : Array[Byte] = Array::make(8, b'\x00')
  for i in 0..<8 {
    a[i] = ciphertext[i]
  }
  let r : Array[Array[Byte]] = []
  for i in 1..<(n + 1) {
    let blk : Array[Byte] = Array::make(8, b'\x00')
    for k in 0..<8 {
      blk[k] = ciphertext[i * 8 + k]
    }
    r.push(blk)
  }
  for j = 5; j >= 0; j = j - 1 {
    for i = n; i >= 1; i = i - 1 {
      let b : Array[Byte] = Array::make(16, b'\x00')
      // (A XOR t) | R[i] first, then decrypt; t = n*j + i. t always fits
      // well under 2^32, so only the low four octets can be nonzero;
      // shifts stay below 32 bits.
      let t = n * j + i
      for k in 0..<4 {
        b[k] = a[k]
      }
      for k in 4..<8 {
        b[k] = (a[k].to_int() ^ ((t >> (8 * (7 - k))) & 0xFF)).to_byte()
      }
      let ri = r[i - 1]
      for k in 0..<8 {
        b[8 + k] = ri[k]
      }
      let out = bc.decrypt_block(Bytes::from_array(b).exact_view())
      for k in 0..<8 {
        a[k] = out[k]
      }
      for k in 0..<8 {
        ri[k] = out[8 + k]
      }
    }
  }
  for i in 0..<8 {
    guard a[i] == kw_iv[i] else {
      raise @error.PgpError::PgpError(
        msg="cipher: key-unwrap integrity check failed",
      )
    }
  }
  let out : Array[Byte] = []
  for blk in r {
    for k in 0..<8 {
      out.push(blk[k])
    }
  }
  Bytes::from_array(out)
}
