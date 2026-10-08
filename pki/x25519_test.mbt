///|
test "x25519 roundtrip and shared secret" {
  // RFC 7748 §6.1 test vector.
  let alice_priv = @pki.x25519_public_of_scalar(
    @primitives.from_hex(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ).exact_view(),
  )
  let bob_priv = @pki.x25519_public_of_scalar(
    @primitives.from_hex(
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ).exact_view(),
  )
  assert_eq(
    @primitives.to_hex(alice_priv.public.exact_view()),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  assert_eq(
    @primitives.to_hex(bob_priv.public.exact_view()),
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let k_ab = @pki.x25519_shared_secret(
    alice_priv.scalar.exact_view(),
    bob_priv.public.exact_view(),
  )
  let k_ba = @pki.x25519_shared_secret(
    bob_priv.scalar.exact_view(),
    alice_priv.public.exact_view(),
  )
  assert_eq(
    @primitives.to_hex(k_ab.exact_view()),
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  assert_eq(k_ab, k_ba)
}

///|
test "x25519 secret wire mpi is big-endian 255-bit" {
  let key = @pki.x25519_public_of_scalar(
    @primitives.from_hex(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ).exact_view(),
  )
  // Clamped: low 3 bits clear, bit 254 set, bit 255 clear.
  let mpi = key.wire_mpi()
  assert_eq(mpi.length(), 34)
  assert_eq(mpi[0], b'\x00')
  assert_eq(mpi[1], b'\xFF')
  // Big-endian: last octet equals the clamped little-endian first octet
  // (scalar starts 0x77; clamp clears the low three bits).
  assert_eq(mpi[33].to_int(), 0x77 & 0xF8)
  // Round-trip through the wire decoder.
  let re = @pki.x25519_secret_of_wire_mpi(mpi[2:mpi.length()].exact_view())
  assert_eq(re.scalar, key.scalar)
  assert_eq(re.public, key.public)
}

///|
test "curve25519 oid" {
  let oid = @pki.curve25519_oid()
  assert_eq(oid[0], b'\x0A')
  assert_eq(
    @primitives.to_hex(oid[1:oid.length()].exact_view()),
    "2b060104019755010501",
  )
}
