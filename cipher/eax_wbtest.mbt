///|
/// RFC 4493 §2.4 CMAC-AES128 known-answer tests (the MAC inside EAX). This
/// is white-box only because `cmac` is an internal building block.
test "cmac-aes128 RFC 4493 vectors" {
  let key = @primitives.from_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let msg = @primitives.from_hex(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
  )
  let cases : Array[(Int32, String)] = [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
  ]
  for c in cases {
    let (len, want) = c
    assert_eq(
      @primitives.to_hex(cmac(bc, msg[0:len])),
      want,
      msg="CMAC over \{len} octets",
    )
  }
}
