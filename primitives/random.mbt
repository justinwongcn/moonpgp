///|
/// Cryptographically strong random bytes from the platform entropy source.
///
/// This deliberately does NOT go through `@random.Rand::new()`: the standard
/// library silently falls back to a fixed seed when the platform cannot
/// provide entropy, which is catastrophic for key/session material. Here a
/// failed entropy read is a hard error.
pub fn random_bytes(n : Int) -> Bytes raise {
  guard n >= 0 else { @error.fail("random_bytes: negative length") }
  let out : Array[Byte] = Array(capacity=n)
  while out.length() < n {
    let want = @error.require(
      @env.rand(if n - out.length() < 256 { n - out.length() } else { 256 }),
      "platform entropy source unavailable; refusing to generate key material with a deterministic fallback",
    )
    for b in want {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}

///|
/// A uniform random integer in `[0, max)` — used for Miller-Rabin bases and
/// PKCS#1 padding selection.
pub fn random_below(max : Int) -> Int raise {
  guard max > 0 else { @error.fail("random_below: max must be positive") }
  // Rejection sampling over 31-bit words to avoid modulo bias.
  let limit = 0x7fffffff / max * max
  for ;; {
    let bs = random_bytes(4)
    let w = (bs[0].to_int() << 24) |
      (bs[1].to_int() << 16) |
      (bs[2].to_int() << 8) |
      bs[3].to_int()
    let v = w & 0x7fffffff
    if v < limit {
      return v % max
    }
  }
}
