///|
/// Encrypt plaintext to a passphrase. Produces an armored PGP MESSAGE with
/// a v4 SKESK (iterated+salted S2K, AES-256 session key wrapped in CFB)
/// followed by a v1 SEIPD packet holding the literal data.
pub fn encrypt_with_password(
  plaintext : BytesView,
  passphrase : String,
  file_name? : String,
) -> String raise {
  let session_key = @primitives.random_bytes(SESSION_KEY_SIZE)
  let skesk = build_skesk(session_key.exact_view(), passphrase)
  let literal = @packet.LiteralPacket::binary(plaintext, file_name?)
  let literal_wire = @packet.serialize_packet(
    @packet.Literal,
    literal.to_body().exact_view(),
  )
  let seipd_ciphertext = seal_seipd(
    session_key.exact_view(),
    literal_wire.exact_view(),
  )
  let w = @packet.Writer::new()
  w.u8(0xC0 | @packet.Skesk.number())
  let skesk_body = skesk.to_body()
  write_packet_length(w, skesk_body.length())
  w.bytes(skesk_body.exact_view())
  w.u8(0xC0 | @packet.Seipd.number())
  write_packet_length(w, seipd_ciphertext.length() + 1)
  w.u8(1)
  w.bytes(seipd_ciphertext.exact_view())
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// Decrypt an (optionally armored) message using a passphrase. Returns the
/// literal data. Compressed packets are transparently decompressed.
pub fn decrypt_with_password(
  message : String,
  passphrase : String,
) -> Bytes raise {
  let armored = @armor.decode(message)
  decrypt_binary_with_password(@armor.ArmorBlock::data(armored), passphrase)
}

///|
/// Same as `decrypt_with_password` but takes binary packet data.
pub fn decrypt_binary_with_password(
  data : BytesView,
  passphrase : String,
) -> Bytes raise {
  let packets = @packet.parse_packets(data)
  let session_key = unwrap_skesk(packets, passphrase)
  for p in packets {
    if p.tag() == @packet.Seipd {
      let seipd = @packet.SeipdPacket::parse(p.body().exact_view())
      guard seipd.version == 1 else {
        @error.fail("api: unsupported SEIPD version \{seipd.version}")
      }
      let bc = @primitives.new_block_cipher(
        @primitives.Aes256,
        session_key.exact_view(),
      )
      let inner = @cipher.seipd_v1_decrypt(bc, seipd.ciphertext.exact_view())
      return extract_literal(inner)
    }
  }
  @error.fail("api: no encrypted data packet found")
}

///|
const SESSION_KEY_SIZE : Int = 32

///|
fn write_packet_length(w : @packet.Writer, length : Int) -> Unit {
  if length < 192 {
    w.u8(length)
  } else if length < 8384 {
    let enc = length - 192 + 192 * 256
    w.u8(enc >> 8)
    w.u8(enc)
  } else {
    w.u8(255)
    w.u32(length)
  }
}

///|
fn build_skesk(
  session_key : BytesView,
  passphrase : String,
) -> @packet.SkeskPacket raise {
  let salt = @primitives.random_bytes(@s2k.SALT_SIZE)
  // ~1 MiB of hashed material: a defensible interactive cost.
  let count_byte = @s2k.encode_count(1024 * 1024)
  let s2k : @s2k.S2k = @s2k.Iterated(@primitives.Sha256, salt, count_byte)
  // The S2K key wraps [algo byte || session key] with CFB, zero IV.
  let wrapping_key = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    SESSION_KEY_SIZE,
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    wrapping_key.exact_view(),
  )
  let plain = Bytes::from_array([@primitives.Aes256.number().to_byte()]).add(
    session_key.to_owned(),
  )
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(16, b'\x00').exact_view(),
    plain.exact_view(),
  )
  @packet.SkeskPacket::{
    cipher_algo: @primitives.Aes256.number(),
    s2k,
    encrypted_session_key: esk,
  }
}

///|
fn unwrap_skesk(
  packets : Array[@packet.RawPacket],
  passphrase : String,
) -> Bytes raise {
  for p in packets {
    if p.tag() == @packet.Skesk {
      let skesk = @packet.SkeskPacket::parse(p.body().exact_view())
      let algo = match @primitives.cipher_algo_of_number(skesk.cipher_algo()) {
        Some(a) => a
        None =>
          @error.fail(
            "api: unsupported cipher algorithm \{skesk.cipher_algo()}",
          )
      }
      let pass = @primitives.utf8_bytes(passphrase)
      if skesk.encrypted_session_key().length() == 0 {
        return skesk.s2k().derive_key(pass.exact_view(), algo.key_size())
      }
      let bc = @primitives.new_block_cipher(
        algo,
        skesk.s2k().derive_key(pass.exact_view(), algo.key_size()).exact_view(),
      )
      let wrapped = @cipher.cfb_decrypt(
        bc,
        Bytes::make(16, b'\x00').exact_view(),
        skesk.encrypted_session_key().exact_view(),
      )
      guard wrapped.length() >= 1 else { @error.fail("api: empty session key") }
      // The wrapped value carries the message cipher algorithm octet.
      let inner_algo = match
        @primitives.cipher_algo_of_number(wrapped[0].to_int()) {
        Some(a) => a
        None => @error.fail("api: unsupported inner cipher algorithm")
      }
      guard wrapped.length() - 1 == inner_algo.key_size() else {
        @error.fail("api: session key length mismatch")
      }
      return wrapped[1:wrapped.length()].to_owned()
    }
  }
  @error.fail("api: no SKESK packet found")
}

///|
fn seal_seipd(session_key : BytesView, inner : BytesView) -> Bytes raise {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    session_key.exact_view(),
  )
  @cipher.seipd_v1_encrypt(bc, inner)
}

///|
/// Walk a decrypted packet stream to the literal data, decompressing on
/// the way. Trailing signature packets (one-pass) are consumed by later
/// layers.
fn extract_literal(inner : BytesView) -> Bytes raise {
  let mut stream = inner
  // At most two nesting levels: SEIPD -> compressed -> literal. A
  // one-pass signature packet may precede the data.
  for _ in 0..<3 {
    let ps = @packet.parse_packets(stream)
    if ps.is_empty() {
      @error.fail("api: empty inner packet stream")
    }
    let tag = ps[0].tag()
    if tag == @packet.Literal {
      return @packet.LiteralPacket::parse(ps[0].body().exact_view()).data()
    }
    if tag == @packet.OnePassSig {
      // Re-parse the rest after the OPS packet.
      if ps.length() > 1 {
        let w = @packet.Writer::new()
        for p in ps[1:ps.length()] {
          w.bytes(
            @packet.serialize_packet(p.tag(), p.body().exact_view()).exact_view(),
          )
        }
        stream = w.to_bytes().exact_view()
        continue
      }
      @error.fail("api: one-pass signature with no data")
    }
    if tag == @packet.Compressed {
      let comp = @packet.CompressedPacket::parse(ps[0].body().exact_view())
      stream = decompress_payload(comp).exact_view()
      continue
    }
    @error.fail(
      "api: expected literal or compressed packet, got tag \{tag.number()}",
    )
  }
  @error.fail("api: literal data not found")
}
