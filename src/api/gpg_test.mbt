///|
/// GnuPG 2.4.5 cross-validation: `gpg --symmetric --cipher-algo AES256
/// --s2k-digest-algo SHA256` over the two-line plaintext, passphrase
/// "testpass123". The message is a v4 SKESK (iterated+salted S2K, no
/// wrapped session key) followed by a v1 SEIPD packet.
test "decrypt a GnuPG-produced symmetric message" {
  let msg = @primitives.from_hex(
    "8c0d04090308740fdd59ae0283e7fad280015a69863af579cf603296fca35c7f73f1927c7e0c9a927d6354b3f26fc5d30fe60c68a4b0b6ea3ac1454ce78962569ebb2344a993c42d00eafeed89a1f3799d93c14a9cf0b3b4dc6e40d4bd81912e33bf7c752f333f4feb7918de632bae31ba8d8e165fc0f4647923f3701f73e67768ce16af3e6b53cb03f573e98b847f76d8",
  )
  let plaintext = @api.decrypt_binary_with_password(
    msg.exact_view(),
    "testpass123",
  )
  assert_eq(
    plaintext,
    @primitives.utf8_bytes(
      "The Magic Words are Squeamish Ossifrage\nsecond line 测试中文\n",
    ),
  )
}

///|
test "wrong passphrase on GnuPG message fails" {
  let msg = @primitives.from_hex(
    "8c0d04090308740fdd59ae0283e7fad280015a69863af579cf603296fca35c7f73f1927c7e0c9a927d6354b3f26fc5d30fe60c68a4b0b6ea3ac1454ce78962569ebb2344a993c42d00eafeed89a1f3799d93c14a9cf0b3b4dc6e40d4bd81912e33bf7c752f333f4feb7918de632bae31ba8d8e165fc0f4647923f3701f73e67768ce16af3e6b53cb03f573e98b847f76d8",
  )
  let raised = try {
    let _ = @api.decrypt_binary_with_password(msg.exact_view(), "nope")
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
