///|
/// F-R3 regression: decode_rfc2047 was quadratic — every failed opener
/// rescanned the whole remaining header (600 KB of adversarial input ran
/// for tens of minutes; a mailreader --last hung on one Subject). The
/// bounded scan window plus the skip-past-"=?" advance made the same
/// inputs run in ~1 ms. The timing printout is the canary: a quadratic
/// reintroduction shows up as a multi-minute test, not a failure.
test "decode_rfc2047 stays linear on adversarial encoded-word shapes (F-R3)" {
  // Dense openers, no closers anywhere: the whole value must come back
  // as lossless raw passthrough.
  let dense = "=?A".repeat(200_000)
  let t0 = @primitives.unix_now()
  assert_eq(@mail.decode_rfc2047(dense), dense)
  let t1 = @primitives.unix_now()
  // Sparse openers with '?'-free runs — the worst per-attempt shape.
  let sparse = "=?A?B?C?D?".repeat(50_000)
  assert_eq(@mail.decode_rfc2047(sparse), sparse)
  let t2 = @primitives.unix_now()
  println("F-R3 dense(600KB): \{t1 - t0} ms; sparse(500KB): \{t2 - t1} ms")
}
