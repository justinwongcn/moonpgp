// Hacker-round probes (2026-11-13), pki facet: F16 Debug redaction never
// reached the pki value carriers — RsaPrivateKey/Ed25519SecretKey/
// X25519SecretKey still derive Debug and print their secret octets.

///|
test "Ed25519SecretKey Debug shows a length, not the seed" {
  let sk : Ed25519SecretKey = {
    seed: Bytes::make(32, 0xAB),
    public: Bytes::make(32, 0xCD),
  }
  let repr = sk.to_repr().to_string()
  assert_true(repr.contains("seed=<32 octets>"))
  assert_true(!repr.contains(@primitives.to_hex(sk.seed.exact_view())))
}

///|
test "X25519SecretKey Debug shows a length, not the scalar" {
  let sk : X25519SecretKey = {
    scalar: Bytes::make(32, 0xAB),
    public: Bytes::make(32, 0xCD),
  }
  let repr = sk.to_repr().to_string()
  assert_true(repr.contains("scalar=<32 octets>"))
  assert_true(!repr.contains(@primitives.to_hex(sk.scalar.exact_view())))
}
