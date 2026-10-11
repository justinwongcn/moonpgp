///|
/// DES/3DES known-answer tests. Single-DES vectors from OpenSSL 3.6.3
/// (`openssl enc -des-ecb -provider legacy`); TripleDES vectors from the
/// Node crypto binding of OpenSSL (`des-ede3-ecb`). The EDE degenerate
/// property (K1=K2=K3 ⇒ 3DES ≡ DES) is asserted structurally.

///|
test "DES single-block known answers (OpenSSL)" {
  let bc = @primitives.new_des(
    @primitives.from_hex("0123456789ABCDEF").exact_view(),
  )
  assert_eq(bc.block_size(), 8)
  let pt = @primitives.utf8_bytes("testtest")
  let ct = bc.encrypt_block(pt.exact_view())
  assert_eq(@primitives.to_hex(ct.exact_view()), "63c9a4a4d73d46ac")
  assert_eq(bc.decrypt_block(ct.exact_view()), pt)
  // Second key / plaintext pair.
  let bc2 = @primitives.new_des(
    @primitives.from_hex("0E329232EA6D0D73").exact_view(),
  )
  let pt2 = @primitives.utf8_bytes("Now is t")
  let ct2 = bc2.encrypt_block(pt2.exact_view())
  assert_eq(@primitives.to_hex(ct2.exact_view()), "ed6c4fcf161c96d4")
  assert_eq(bc2.decrypt_block(ct2.exact_view()), pt2)
  let bc3 = @primitives.new_des(
    @primitives.from_hex("FEDCBA9876543210").exact_view(),
  )
  assert_eq(
    @primitives.to_hex(bc3.encrypt_block(pt.exact_view()).exact_view()),
    "b85340a60f5b9906",
  )
}

///|
test "TripleDES known answers (OpenSSL des-ede3-ecb)" {
  let bc = @primitives.new_des_ede3(
    @primitives.from_hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").exact_view(),
  )
  assert_eq(bc.block_size(), 8)
  let pt = @primitives.utf8_bytes("testtest")
  let ct = bc.encrypt_block(pt.exact_view())
  assert_eq(@primitives.to_hex(ct.exact_view()), "63c9a4a4d73d46ac")
  assert_eq(bc.decrypt_block(ct.exact_view()), pt)
  // Independent key set.
  let bc2 = @primitives.new_des_ede3(
    @primitives.from_hex("0102030405060708090A0B0C0D0E0F101112131415161718").exact_view(),
  )
  let pt2 = @primitives.utf8_bytes("Now is t")
  let ct2 = bc2.encrypt_block(pt2.exact_view())
  assert_eq(@primitives.to_hex(ct2.exact_view()), "f7cfbe5e6c38b35a")
  assert_eq(bc2.decrypt_block(ct2.exact_view()), pt2)
}

///|
test "EDE degenerates to DES when K1=K2=K3" {
  // The classic structural property: with all three subkeys equal the
  // middle (decrypting) stage cancels the outer ones.
  let single = @primitives.new_des(
    @primitives.from_hex("0123456789ABCDEF").exact_view(),
  )
  let triple = @primitives.new_des_ede3(
    @primitives.from_hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").exact_view(),
  )
  let pt = @primitives.utf8_bytes("Now is t")
  assert_eq(
    single.encrypt_block(pt.exact_view()),
    triple.encrypt_block(pt.exact_view()),
  )
  assert_eq(
    single.decrypt_block(pt.exact_view()),
    triple.decrypt_block(pt.exact_view()),
  )
}

///|
test "3DES key must be 24 octets" {
  let raised = try {
    let _ = @primitives.new_des_ede3(
      @primitives.from_hex("00112233445566778899").exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "dispatch routes legacy algorithm numbers" {
  // RFC 9580 §9.3 numbers reach the right implementations.
  assert_eq(@primitives.cipher_algo_of_number(2), Some(@primitives.Tripledes))
  assert_eq(@primitives.cipher_algo_of_number(3), Some(@primitives.Cast5))
  assert_eq(@primitives.Tripledes.key_size(), 24)
  assert_eq(@primitives.Cast5.key_size(), 16)
  assert_eq(@primitives.Tripledes.number(), 2)
  assert_eq(@primitives.Cast5.number(), 3)
}
