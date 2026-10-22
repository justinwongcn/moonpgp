///|
/// White-box checks of the Argon2 internals against RFC 9106 §5.3, so the
/// first divergence from the published KAT can be pinpointed.
test "argon2 internals: H0 and the first expanded block" {
  let pass = Bytes::make(32, b'\x01')
  let salt = Bytes::make(16, b'\x02')
  let secret = Bytes::make(8, b'\x03')
  let ad = Bytes::make(12, b'\x04')
  let h0 = argon2_h0(pass, salt, secret, ad, 32, 32, 3, 4)
  assert_eq(
    to_hex(h0),
    "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997",
  )
  // B[0][0] = H'^1024(H0 || LE32(0) || LE32(0)).
  let input : Array[Byte] = []
  for b in h0 {
    input.push(b)
  }
  input.push(b'\x00')
  input.push(b'\x00')
  input.push(b'\x00')
  input.push(b'\x00')
  input.push(b'\x00')
  input.push(b'\x00')
  input.push(b'\x00')
  input.push(b'\x00')
  let block = argon2_h_prime(Bytes::from_array(input), 1024)
  assert_eq(to_hex(block[0:16]), "43bd7106f1092e6bbe218a91275c9ff6")
}

///|
/// Pass-by-pass block trace of the RFC 9106 §5.3 setup, matching the
/// published KAT's "After pass N Block 0000 / 0031" lines.
test "argon2 internals: pass trace (RFC 9106 KAT)" {
  let pass = Bytes::make(32, b'\x01')
  let salt = Bytes::make(16, b'\x02')
  let secret = Bytes::make(8, b'\x03')
  let ad = Bytes::make(12, b'\x04')
  let h0 = argon2_h0(pass, salt, secret, ad, 32, 32, 3, 4)
  let inst = argon2_instance(4, 32)
  for lane in 0..<4 {
    for index in 0..<2 {
      let buf : Array[Byte] = []
      for b in h0 {
        buf.push(b)
      }
      push_le32(buf, index)
      push_le32(buf, lane)
      let block = argon2_h_prime(Bytes::from_array(buf), 1024)
      argon2_store_block(
        inst.mem,
        (lane * inst.lane_len + index) * ARGON2_BLOCK_WORDS,
        block,
      )
    }
  }
  // Block 0 is never rewritten in pass 0 (it is the H' output above); the
  // KAT's pass 0 line for it is simply its little-endian words.
  let want_block0 : Array[String] = [
    "6b2e09f10671bd43f69f5c27918a21bedea7810ea41290e16787f7171870f893", "3653ec9d01583df969ef53a72d1e1fd335635631744ab54f599512e96a37ab6e",
    "942363968ce597a4a22448c0bdad5760a5f80662b6fa8748a0f9b9ce392f719f",
  ]
  let want_block31 : Array[String] = [
    "377fa81666dc7f2b50e586398a9c39c86f732732a550924a81f88b28683ea8e5", "4d4b435cea35caa6c582210d99ad1359d087971b36fd6d77a55222a93754c692",
    "d723359b485f509bcb78824f4237511135bc8cc6e83b18750b012846a40f346a",
  ]
  for p in 0..<3 {
    for slice in 0..<4 {
      for lane in 0..<4 {
        argon2_fill_segment(inst, p, lane, slice, 3)
      }
    }
    assert_eq(
      hex_words(inst.mem, 0, 4),
      want_block0[p],
      msg="pass \{p} block 0",
    )
    assert_eq(
      hex_words(inst.mem, 31 * 128 + 124, 4),
      want_block31[p],
      msg="pass \{p} block 31",
    )
  }
}

///|
/// Fixed-width hex of `len` words starting at `off`.
fn hex_words(mem : FixedArray[UInt64], off : Int32, len : Int32) -> String {
  let mut out = ""
  for k in off..<(off + len) {
    out = out + hex_word(mem[k])
  }
  out
}

///|
/// Fixed-width 16-digit hex of a 64-bit word, matching the KAT file's
/// "words[124..127]" formatting.
fn hex_word(w : UInt64) -> String {
  let s = w.to_string(radix=16)
  let out = StringBuilder()
  for _ in 0..<(16 - s.length()) {
    out.write_string("0")
  }
  out.write_string(s)
  out.to_string()
}
