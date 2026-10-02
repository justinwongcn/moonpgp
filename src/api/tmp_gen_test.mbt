///|
test "gen armor for gpg" {
  let plaintext = @primitives.utf8_bytes(
    "The Magic Words are Squeamish Ossifrage\nsecond line 测试中文\n",
  )
  let armored = @api.encrypt_with_password(plaintext, "testpass123")
  println("===ARMOR-START===")
  println(armored)
  println("===ARMOR-END===")
}
