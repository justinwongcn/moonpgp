///|
/// Regression for audit F1: the bit-reader limit comparison used to run in
/// Int32, so a cursor near 2^31 bits wrapped the guard into passing and the
/// read went out of bounds (SIGABRT). The cursor is Int64 now; the same
/// near-wrap cursor on a tiny buffer must raise "truncated", not crash.
test "bzip2 bit reader rejects a near-2^31 cursor instead of wrapping" {
  let bits : BzBits = { data: Bytes::make(4, b'\x00')[0:4], pos: 2147483647L, }
  let r = try {
    ignore(bits.get64(48))
    "guard-passed"
  } catch {
    e => "raised: \{e}"
  }
  assert_eq(r, "raised: Malformed(compress: truncated bzip2 stream)")
  // Also just past the exact wrap point of the old Int32 arithmetic.
  let bits2 : BzBits = { data: Bytes::make(4, b'\x00')[0:4], pos: 2147483648L, }
  let r2 = try {
    ignore(bits2.get(1))
    "guard-passed"
  } catch {
    e => "raised: \{e}"
  }
  assert_eq(r2, "raised: Malformed(compress: truncated bzip2 stream)")
  // Sanity: a legitimate read at the end of a small stream still passes.
  let bits3 : BzBits = { data: Bytes::make(6, b'\xff')[0:6], pos: 40L, }
  assert_eq(bits3.get(8), 0xFF)
}
