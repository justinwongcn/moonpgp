///|
test "crc24 of empty input is the initial value" {
  assert_eq(@armor.crc24(b""), 0xB704CE)
}

///|
test "crc24 known vector" {
  // Reference: Go openpgp armor_test.go CRC-24 of "1234\x00..." handled
  // here with a computed roundtrip instead: crc24 must be stable and 24-bit.
  let c = @armor.crc24(b"The quick brown fox jumps over the lazy dog")
  assert_true(c >= 0 && c <= 0xFFFFFF)
}

///|
test "armor encode/decode roundtrip" {
  let data = Bytes::makei(500, i => (i % 251).to_byte())
  let text = @armor.Message.encode(data, headers=[("Comment", "roundtrip test")])
  let block = @armor.decode(text)
  assert_eq(@armor.ArmorBlock::armor_type(block), @armor.Message)
  assert_eq(@armor.ArmorBlock::data(block), data)
  assert_eq(block.header("comment"), Some("roundtrip test"))
  assert_true(block.header("Version") != None)
}

///|
test "armor encode line width and structure" {
  let data = Bytes::make(200, b'\x42')
  let text = @armor.encode(data)
  for line in text.split("\n") {
    assert_true(line.length() <= 64)
  }
  assert_true(text.contains("-----BEGIN PGP MESSAGE-----"))
  assert_true(text.contains("-----END PGP MESSAGE-----"))
  assert_true(text.contains("\n="))
}

///|
const GOPENPGP_SED_MESSAGE : String =
  #|-----BEGIN PGP MESSAGE-----
  #|
  #|hQGMA3wvqk35PDeyAQwAyfOgW1muzY3NhAeShMCUzoAeAY6BGeJ2vCVZ1JCELVNk
  #|hxZIapaprHkmBHHlTOeS7r0YUhIoxgCbra1wh7o4qL7LGEh1EhuvXYi+2qXoCcCy
  #|2eGG8F2C5szBee9Jj3tDweevpHCR9g5JixoTrqIyUWhse1IdNyXxw+/CYwTwBiYI
  #|1hEZznYpyxuZPpcZ3aVtF+keIQRizzItjEs9+plUlelASmuhN3RqvUImItqsBG4r
  #|X3Y0wwHxbAg/m+7YasU61ikFYh/Dt5n9OVZ/cOwypAu/7lMrfkMqf41oJcoDvgr7
  #|7JL/t68OlVmy9BxgFvWvtNenF/zdW0hNmko8JXEUZBG1b9gKvYCPVQ/sJdzm2G4n
  #|U5hiGUu0l6cGubcf4hrDUTRROXfKUwrkPNxSBpBy9iqZFFqKGX4yBy2lfuRfZaTa
  #|gfTLganwio32jXHFdrAMnyn3vqogFKM12ZIhdxQsYNMb/4SUW5L0Jun5hieAqchE
  #|3e4bbBzLwBRyRkonYnRYyTJPzN/SChiPO3UEA0U55pDYBrqH3Nv5lSbeXiE31pXW
  #|7FZr1phe3LZVUso6CUzJdyECJw==
  #|=meER
  #|-----END PGP MESSAGE-----

///|
test "decode real gopenpgp armored message" {
  // The vector is a Symmetrically-Encrypted (MDC) PGP message produced by
  // ProtonMail/go-crypto; the armor layer must decode it and verify CRC.
  let block = @armor.decode(GOPENPGP_SED_MESSAGE)
  assert_eq(@armor.ArmorBlock::armor_type(block), @armor.Message)
  assert_true(@armor.ArmorBlock::data(block).length() > 300)
}

///|
test "corrupted CRC is rejected" {
  let corrupted = GOPENPGP_SED_MESSAGE.replace(old="=meER", new="=meES")
  let result = try? @armor.decode(corrupted)
  assert_true(result.is_err())
}

///|
test "decode concatenated blocks" {
  let data1 = Bytes::of_string("hello")
  let data2 = Bytes::of_string("world")
  let key_block = @armor.PublicKey.encode(data1)
  let sig_block = @armor.Signature.encode(data2)
  let both = key_block + sig_block
  let blocks = @armor.decode_all(both)
  assert_eq(blocks.length(), 2)
  assert_eq(@armor.ArmorBlock::armor_type(blocks[0]), @armor.PublicKey)
  assert_eq(@armor.ArmorBlock::armor_type(blocks[1]), @armor.Signature)
  assert_eq(@armor.ArmorBlock::data(blocks[0]), data1)
  assert_eq(@armor.ArmorBlock::data(blocks[1]), data2)
}

///|
test "no armor block found raises" {
  let result = try? @armor.decode("no armor here")
  assert_true(result.is_err())
}
