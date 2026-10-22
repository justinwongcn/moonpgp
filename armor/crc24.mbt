///|
/// CRC-24 over OpenPGP armored data (RFC 9580 §6.1). Polynomial 0x864CFB,
/// initial value 0xB704CE, no final XOR. ~30 lines and permanently ours:
/// this is PGP-wire material, never a replaceable third-party concern.
pub fn crc24(data : BytesView) -> Int32 {
  let mut crc = 0xB704CE
  for octet in data {
    crc = crc ^ (octet.to_int() << 16)
    for _ in 0..<8 {
      crc = crc << 1
      if (crc & 0x1000000) != 0 {
        crc = crc ^ 0x1864CFB
      }
    }
  }
  crc & 0xFFFFFF
}
