///|
/// CLI helper tests for cmd/main. The command entry itself is exercised
/// by the smoke script; these cover the pure helpers.

///|
test "basename slices by code units, not character counts (M2)" {
  // A supplementary-plane char (1 char = 2 code units) before the last
  // '/' drifted the character-index scan against the UTF-16 slice: the
  // separator itself survived into the "basename" (F22 class, the
  // mailreader instance is already fixed — this is the cmd twin).
  assert_eq(basename("a😀b/file.txt"), "file.txt")
  assert_eq(basename("/tmp/plain.asc"), "plain.asc")
  assert_eq(basename("plain.asc"), "plain.asc")
  assert_eq(basename("dir/sub/😀.asc"), "😀.asc")
  assert_eq(basename("/"), "")
}

///|
test "parse_bits fails loudly on garbage (M3, m5 convention)" {
  // No explicit bits: the RFC 9580 floor applies.
  assert_eq(parse_bits(["u", "p", "k"]) catch { _ => 0 }, 3072)
  assert_eq(parse_bits(["u", "p", "k", "4096"]) catch { _ => 0 }, 4096)
  // Garbage used to silently fall back to 3072; it must fail loudly
  // (review finding m5: an unparseable parameter never degrades quietly).
  let raised = try {
    ignore(parse_bits(["u", "p", "k", "abc"]))
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}
