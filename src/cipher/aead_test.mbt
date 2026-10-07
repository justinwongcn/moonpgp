///|
/// draft-ietf-openpgp-rfc4880bis A.4: a full tag-20 AEAD sample (AES-128,
/// OCB, chunk octet 14, session key from the RFC's own SKESK). The
/// expected bytes are the RFC's chunk-0 ciphertext+tag and final tag.
test "aead chunk layer matches the rfc4880bis A.4 sample" {
  let key = @primitives.from_hex("d1f01ba30e130aa7d2582c16e050ae44")
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let header5 = @primitives.from_hex("d40107020e")
  let iv = @primitives.from_hex("5ed2bc1e470abe8f1d644c7a6c8a56")
  let plain = @primitives.from_hex(
    "cb1462000000000048656c6c6f2c20776f726c64210a",
  )
  let packet_bytes = @cipher.aead_seal(
    bc,
    @cipher.Ocb,
    header5.exact_view(),
    iv.exact_view(),
    14,
    plain.exact_view(),
  )
  assert_eq(
    @primitives.to_hex(packet_bytes),
    "7b0f7701196611a154ba9c2574cd056284a8ef68035c" +
    "623d93cc708a43211bb6eaf2b27f7c18" +
    "d571bcd83b20add3a08b73af15b9a098",
  )
  let opened = @cipher.aead_open(
    bc,
    @cipher.Ocb,
    header5.exact_view(),
    iv.exact_view(),
    14,
    packet_bytes.exact_view(),
  )
  assert_eq(opened, plain)
}

///|
/// Multi-chunk round-trip (chunk octet 0 = 64-octet chunks), including an
/// exact-multiple payload (no empty trailing chunk) and an empty payload
/// (one empty chunk tag plus the final tag).
test "aead multi-chunk and empty payloads round-trip" {
  let key = @primitives.random_bytes(32)
  let bc = @primitives.new_block_cipher(@primitives.Aes256, key.exact_view())
  let header5 = @primitives.from_hex("d4010902ff")
  for octet in [0, 6] {
    for len in [0, 1, 63, 64, 65, 200] {
      let iv = @primitives.random_bytes(15)
      let plain = @primitives.random_bytes(len)
      let packet_bytes = @cipher.aead_seal(
        bc,
        @cipher.Ocb,
        header5.exact_view(),
        iv.exact_view(),
        octet,
        plain.exact_view(),
      )
      let opened = @cipher.aead_open(
        bc,
        @cipher.Ocb,
        header5.exact_view(),
        iv.exact_view(),
        octet,
        packet_bytes.exact_view(),
      )
      assert_eq(opened, plain)
    }
  }
}

///|
/// GCM uses the same chunk layer with a 12-octet IV and the mode octet 3.
test "aead gcm round-trip" {
  let key = @primitives.random_bytes(16)
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let header5 = @primitives.from_hex("d401070300")
  let iv = @primitives.random_bytes(12)
  let plain = @primitives.random_bytes(150)
  let packet_bytes = @cipher.aead_seal(
    bc,
    @cipher.Gcm,
    header5.exact_view(),
    iv.exact_view(),
    0,
    plain.exact_view(),
  )
  assert_eq(
    @cipher.aead_open(
      bc,
      @cipher.Gcm,
      header5.exact_view(),
      iv.exact_view(),
      0,
      packet_bytes.exact_view(),
    ),
    plain,
  )
}

///|
/// A single flipped bit anywhere — chunk tag, final tag, or the chunk
/// index inside the AD — must fail authentication.
test "aead rejects tampering" {
  let key = @primitives.random_bytes(16)
  let bc = @primitives.new_block_cipher(@primitives.Aes128, key.exact_view())
  let header5 = @primitives.from_hex("d40107020e")
  let iv = @primitives.random_bytes(15)
  let plain = @primitives.random_bytes(40)
  let packet_bytes = @cipher.aead_seal(
    bc,
    @cipher.Ocb,
    header5.exact_view(),
    iv.exact_view(),
    14,
    plain.exact_view(),
  )
  let arr : Array[Byte] = []
  for i in 0..<packet_bytes.length() {
    arr.push(packet_bytes[i])
  }
  arr[0] = (arr[0].to_int() ^ 1).to_byte()
  let bad_chunk = Bytes::from_array(arr)
  let raised = try {
    let _ = @cipher.aead_open(
      bc,
      @cipher.Ocb,
      header5.exact_view(),
      iv.exact_view(),
      14,
      bad_chunk.exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Flip the last byte of the final tag.
  let arr2 : Array[Byte] = []
  for i in 0..<packet_bytes.length() {
    arr2.push(packet_bytes[i])
  }
  let last = packet_bytes.length() - 1
  arr2[last] = (arr2[last].to_int() ^ 1).to_byte()
  let raised2 = try {
    let _ = @cipher.aead_open(
      bc,
      @cipher.Ocb,
      header5.exact_view(),
      iv.exact_view(),
      14,
      Bytes::from_array(arr2).exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
  // A changed chunk octet changes the AD and must also fail.
  let raised3 = try {
    let _ = @cipher.aead_open(
      bc,
      @cipher.Ocb,
      @primitives.from_hex("d40107020f").exact_view(),
      iv.exact_view(),
      15,
      packet_bytes.exact_view(),
    )
    false
  } catch {
    _ => true
  }
  assert_true(raised3)
}
