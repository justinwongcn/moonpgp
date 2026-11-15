// Hacker-round probes (2026-11-13): F7 residual — END line whitespace.

///|
/// BEGIN tolerates trailing transport whitespace (existing behavior, the
/// parity anchor); the F7 rewrite made END an exact whole-line match, so
/// the mirror shape now hard-fails as invalid base64.
test "armor END line tolerates trailing transport whitespace like BEGIN" {
  let block = @armor.decode(
    "-----BEGIN PGP MESSAGE-----\n\naGVsbG8=\n-----END PGP MESSAGE----- \n",
  )
  assert_eq(block.data(), b"hello")
}

///|
/// Control (must stay green): BEGIN with trailing whitespace still parses.
test "armor BEGIN line tolerates trailing transport whitespace" {
  let block = @armor.decode(
    "-----BEGIN PGP MESSAGE----- \n\naGVsbG8=\n-----END PGP MESSAGE-----\n",
  )
  assert_eq(block.data(), b"hello")
}
