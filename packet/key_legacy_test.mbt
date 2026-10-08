///|
/// Secret-key packet wire-shape regressions found in the 2026-10-08
/// review. Both concern the *legacy* S2K usage form, where the usage octet
/// is itself the cipher algorithm id (RFC 4880 §5.5.3 / RFC 9580 Table 2).

///|
/// `to_body` used to write `s2k_usage` and then `cipher_algo` again, so a
/// legacy packet gained a spurious octet and every re-serialization
/// shifted the IV by one byte — `PrivateKey::to_bytes` (import then
/// export) corrupted such keys.
test "legacy secret key body carries a single usage octet" {
  let public : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: 0,
    algo: @packet.RsaEncryptOrSign,
    params: [b"\x01\x02\x03", b"\x01\x00\x01"],
  }
  let iv : Bytes = Bytes::make(16, b'\xA5')
  let material : Bytes = Bytes::make(24, b'\x5A')
  let secret : @packet.SecretKeyPacket = {
    public,
    s2k_usage: 7, // AES-128 as a legacy cipher-id usage octet
    cipher_algo: 7,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv,
    secret_material: material,
    dummy: false,
  }
  let body = secret.to_body()
  let public_len = public.to_body().length()
  assert_eq(body[public_len].to_int(), 7)
  // The IV starts immediately after that one octet.
  assert_eq(body[public_len + 1:public_len + 17].to_owned(), iv)
  let reparsed = @packet.SecretKeyPacket::parse(body.exact_view())
  assert_eq(reparsed.s2k_usage, 7)
  assert_eq(reparsed.iv, iv)
  assert_eq(reparsed.secret_material, material)
}

///|
/// RFC 9580 §3.7.2.1: the S2K usage rows that are not for generation are
/// "for reading version 4 and earlier keys only … Version 6 secret keys
/// using these formats MUST be rejected". The cipher-id form was accepted
/// for v6 keys and silently used an implied Simple/MD5 S2K.
test "a v6 secret key with a legacy cipher-id usage octet is rejected" {
  let public : @packet.PublicKeyPacket = {
    version: 6,
    creation_time: 0,
    algo: @packet.Ed25519,
    params: [Bytes::make(32, b'\x11')],
  }
  let body = public
    .to_body()
    .add(b"\x07")
    .add(Bytes::make(16, b'\x00'))
    .add(Bytes::make(32, b'\x22'))
  try @packet.SecretKeyPacket::parse(body.exact_view()) catch {
    _ => ()
  } noraise {
    _ => fail("a v6 secret key with a legacy usage octet was accepted")
  }
}
