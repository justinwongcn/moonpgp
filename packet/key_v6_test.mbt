///|
/// RFC 9580 §5.5.3: for a v6 secret key the 1-octet S2K parameter count
/// covers exactly the fields that follow it. It used to be treated as a
/// mere "enough octets left" guard, so a wrong count was accepted and the
/// fields were split wherever the reader happened to land.

///|
/// Build a v6 secret-key body with S2K usage 253 (AEAD):
/// count | cipher | aead | spec-length | specifier | nonce | material.
/// `count_delta` perturbs the declared count.
fn v6_aead_secret_body(
  public : @packet.PublicKeyPacket,
  count_delta : Int32,
) -> Bytes raise {
  let spec = @s2k.Iterated(@primitives.Sha256, Bytes::make(8, b'\x02'), 96).encode()
  let nonce = Bytes::make(15, b'\x03') // OCB nonce
  let params_len = 1 + 1 + 1 + spec.length() + nonce.length() + count_delta
  let w = @packet.Writer::new()
  w.bytes(public.to_body().exact_view())
  w.u8(253)
  w.u8(params_len)
  w.u8(@primitives.Aes256.number())
  w.u8(2) // AEAD mode 2 = OCB, i.e. a 15-octet nonce
  w.u8(spec.length())
  w.bytes(spec.exact_view())
  w.bytes(nonce.exact_view())
  w.bytes(Bytes::make(32, b'\x04').exact_view())
  w.to_bytes()
}

///|
test "a v6 secret key must consume exactly its declared S2K parameter count" {
  let public : @packet.PublicKeyPacket = {
    version: 6,
    creation_time: 0,
    algo: @packet.Ed25519,
    params: [Bytes::make(32, b'\x11')],
  }
  // The honest count parses and the fields land where the count says.
  let good = @packet.SecretKeyPacket::parse(
    v6_aead_secret_body(public, 0).exact_view(),
  )
  assert_eq(good.s2k_usage, 253)
  assert_eq(good.cipher_algo, @primitives.Aes256.number())
  assert_eq(good.aead_algo, 2)
  assert_eq(good.iv.length(), 15)
  assert_eq(good.secret_material.length(), 32)
  // One octet more or less must be rejected, not silently mis-split.
  for delta in [1, -1] {
    try
      @packet.SecretKeyPacket::parse(
        v6_aead_secret_body(public, delta).exact_view(),
      )
    catch {
      @error.Malformed(_) => ()
      _ => fail("expected a PgpError for the wrong parameter count")
    } noraise {
      _ => fail("a v6 secret key with count_delta \{delta} was accepted")
    }
  }
}
