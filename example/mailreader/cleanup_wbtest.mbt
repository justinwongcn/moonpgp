// Cleanup round (2026-11-13), E6: the D2 delivery gate.

///|
test "delivery gate refuses NotSigned/NoVerifier with a non-zero exit (E6)" {
  // No verification attempted: clean.
  assert_true(delivery_failure(0, []) is None)
  // Clean verification: clean.
  assert_true(delivery_failure(0, [@api.Ok]) is None)
  // The two statuses that used to slip through the old branch pair.
  assert_true(delivery_failure(0, [@api.NotSigned]) is Some(_))
  assert_true(delivery_failure(0, [@api.NoVerifier]) is Some(_))
  // Revoked/expired/failed keep failing, and reported errors are
  // counted even in the (should-not-happen) Ok pairing.
  assert_true(delivery_failure(0, [@api.Failed]) is Some(_))
  assert_true(delivery_failure(0, [@api.KeyRevoked]) is Some(_))
  assert_true(delivery_failure(0, [@api.Expired]) is Some(_))
  assert_true(delivery_failure(1, [@api.Ok]) is Some(_))
}
