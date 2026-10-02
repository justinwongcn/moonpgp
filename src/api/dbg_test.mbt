///|
test "debug cleartext" {
  let key = @api.generate_key("CT <ct@example.com>", bits=1024)
  let text = "hello cleartext\n"
  let message = @api.sign_cleartext(text, key)
  println("===MESSAGE===\n\{message}===END===")
  let pub_key = key.to_public()
  println("pub key id: \{@primitives.to_hex(pub_key.key_id())}")
  let block = @armor.decode(message)
  ignore(block)
  // parse the sig from the message
  let lines : Array[StringView] = message.split("\n").collect()
  let buf = StringBuilder::new()
  let mut started = false
  for l in lines {
    if l.has_prefix("-----BEGIN PGP SIGNATURE-----") {
      started = true
    }
    if started {
      buf.write_stringview(l)
      buf.write_char('\n')
    }
  }
  let sig_block = @armor.decode(buf.to_string())
  let packets = @packet.parse_packets(@armor.ArmorBlock::data(sig_block).view())
  for p in packets {
    if p.tag() == @packet.Signature {
      let sig = @packet.SignaturePacket::parse(p.body().view())
      match @packet.SignaturePacket::issuer_key_id(sig) {
        Some(id) => println("sig issuer: \{@primitives.to_hex(id)}")
        None => println("sig issuer: NONE")
      }
      println(
        "sig type: \{@packet.SignaturePacket::sig_type(sig).number()} hash: \{@packet.SignaturePacket::hash_algo(sig)}",
      )
    }
  }
}
