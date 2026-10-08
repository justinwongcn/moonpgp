///|
/// RFC 9580 Appendix A.8 (X25519 + AEAD-OCB), A.9 (AEAD-EAX) and A.10
/// (AEAD-OCB) v2 SEIPD samples. Each test derives the message key and
/// nonce prefix from the published session key and salt, opens the sample
/// ciphertext, and compares the plaintext with the RFC's literal-data
/// packet plus padding packet.

///|
/// Literal Data packet with the string contents "Hello, world!" from the
/// A.8.4/A.9.4/A.10.4/A.11.4 samples.
const A_HELLO_LITERAL : String = "cb1362000000000048656c6c6f2c20776f726c6421"

///|
test "seipd v2 opens RFC 9580 A.8.3 (X25519 + OCB)" {
  let session_key = @primitives.from_hex("dd708f6fa1ed65114d68d2343e7c2f1d")
  let salt = @primitives.from_hex(
    "616416535be0b0716d60e052a56c4c407f9eb36b0efafe9ad0a0df9b033c69a2",
  )
  let cipher = @primitives.from_hex(
    "1ba9ebd2c0ec95bf569d25c999ee4a3de17058f40dfa8b4c682be3fbbbd7b27eb0f59bb5005f80c7c6f40388c30ad406ab0513dcd6f9fd737656286e1177d00f888adb31c4",
  )
  let plain = seipd_v2_open_sample(
    session_key, salt, 2, 6, cipher, "45 12 f7 14 9d 86 33 41 52 7c 65 67 d5 bf fc 42 5f af 32 50 21 2f f9",
  )
  assert_eq(
    @primitives.to_hex(plain),
    A_HELLO_LITERAL + "d50ec5a293072991628147d72c8f86b7",
  )
}

///|
test "seipd v2 opens RFC 9580 A.9.3 (EAX)" {
  let session_key = @primitives.from_hex("3881bafe985412459b86c36f98cb9a5e")
  let salt = @primitives.from_hex(
    "9ff90e3b321964f3a42913c8dcc6619325015227efb7eaeaa49f04c2e674175d",
  )
  let cipher = @primitives.from_hex(
    "4a3d226ed6afcb9ca9ac122c1470e11c63d4c0ab241c6a938ad48bf99a5a99b90bba8325de61047540258ab7959a95ad051dda96eb15431dfef5f5e2255ca78261546e339a",
  )
  let plain = seipd_v2_open_sample(
    session_key, salt, 1, 6, cipher, "b5 04 22 ac 1c 26 be 9d dd 83 1d 5b bb 36 b6 4f 78 b8 33 f2 e9 4a 60 c0",
  )
  assert_eq(
    @primitives.to_hex(plain),
    A_HELLO_LITERAL + "d50eae5bf0cd6705500355816cb0c8ff",
  )
}

///|
test "seipd v2 opens RFC 9580 A.10.3 (OCB, v6 SKESK session key)" {
  let session_key = @primitives.from_hex("28e79ab82397d3c63de24ac217d7b791")
  let salt = @primitives.from_hex(
    "20a661f731fc9a3032b5623326027e3a5d8db5748ebeff0b0c5910d09ecdd641",
  )
  let cipher = @primitives.from_hex(
    strip_spaces(
      "ff9fd38562758035bc49754ce1bf3fffa7dad0a3b8104f5133cf42a4100a83eef4ca1b4801a8846bf42bcda7c8ce9d65e212f301cbcd98fdca de694a877ad4247323f6e857",
    ),
  )
  let plain = seipd_v2_open_sample(
    session_key, salt, 2, 6, cipher, "71 66 2a 11 ee 5b 4e 08 14 4e 6d e8 83 a0 09 99 eb de 12 bb 57 0d cf",
  )
  assert_eq(
    @primitives.to_hex(plain),
    A_HELLO_LITERAL + "d50eae6aa1649b56aa835b2613902bd2",
  )
}

///|
test "seipd v2 opens RFC 9580 A.11.3 (GCM, v6 SKESK session key)" {
  let session_key = @primitives.from_hex("1936fc8568980274bb900d8319360c77")
  let salt = @primitives.from_hex(
    "fcb94490bcb98bbdc9d106c6090266940f72e89edc21b5596b1576b101ed0f9f",
  )
  let cipher = @primitives.from_hex(
    strip_spaces(
      "fc6fc6d65bbfd24dcd0790966e6d1e85a30053784cb1d8b6a0699ef12155a7b2ad6258531b57651fd7777912fa95e35d9b40216f69a4c248db28ff4331f1632907399e6ff9",
    ),
  )
  let plain = seipd_v2_open_sample(
    session_key, salt, 3, 6, cipher, "ea 14 38 80 3c b8 a4 77 40 ce 9b 54 c3 38 77 8d 4d 2b dc 2b",
  )
  assert_eq(
    @primitives.to_hex(plain),
    A_HELLO_LITERAL + "d50e1ce2269a9eddef81032172b7ed7c",
  )
}

///|
test "seipd v2 seal/open round trip across an exact chunk boundary" {
  let session_key = @primitives.from_hex("000102030405060708090a0b0c0d0e0f")
  let salt = @primitives.from_hex(
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
  )
  // chunk octet 0 -> 64-octet chunks, so 130 octets cross it twice.
  let header5 = @primitives.from_hex("d202070206")
  for mode in [@cipher.Ocb, @cipher.Eax, @cipher.Gcm] {
    let (key, iv) = @cipher.seipd_v2_kdf(
      session_key,
      salt,
      16,
      mode,
      header5.exact_view(),
    )
    let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
    for len in [0, 1, 63, 64, 65, 130] {
      let plain = Bytes::make(len, b'\x41')
      let ct = @cipher.seipd_v2_seal(
        bc,
        mode,
        header5.exact_view(),
        iv.exact_view(),
        0,
        plain.exact_view(),
      )
      assert_eq(
        @cipher.seipd_v2_open(
          bc,
          mode,
          header5.exact_view(),
          iv.exact_view(),
          0,
          ct.exact_view(),
        ),
        plain,
        msg="mode \{mode.number()} len \{len}",
      )
    }
  }
}

///|
/// Shared helper: derive the key/nonce for a published sample, check the
/// HKDF output against the RFC, then open the ciphertext.
fn seipd_v2_open_sample(
  session_key : Bytes,
  salt : Bytes,
  aead : Int,
  chunk_octet : Int,
  cipher : Bytes,
  want_hkdf_hex : String,
) -> Bytes raise {
  let mode = match @cipher.aead_mode_of_number(aead) {
    Some(m) => m
    None => fail("bad AEAD id")
  }
  let header5 = Bytes::from_array([
    0xD2,
    2,
    7,
    aead.to_byte(),
    chunk_octet.to_byte(),
  ])
  let (key, iv) = @cipher.seipd_v2_kdf(
    session_key.exact_view(),
    salt.exact_view(),
    16,
    mode,
    header5.exact_view(),
  )
  assert_eq(
    @primitives.to_hex(key.add(iv)),
    strip_spaces(want_hkdf_hex),
    msg="HKDF output",
  )
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  @cipher.seipd_v2_open(
    bc,
    mode,
    header5.exact_view(),
    iv.exact_view(),
    chunk_octet,
    cipher.exact_view(),
  )
}

///|
/// Remove the spaces used to group the RFC's hex dumps.
fn strip_spaces(s : String) -> String {
  let out = StringBuilder()
  for c in s {
    if c != ' ' {
      out.write_char(c)
    }
  }
  out.to_string()
}
