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

///|
test "uidvalidity_mismatch branches the --resync path (leftover #3)" {
  // The state file lives in /tmp and persists across runs — a fixed
  // host would see a stale baseline here (the exact pollution the
  // round-2 notes flagged). Unique host per run keeps the no-baseline
  // assertion honest.
  let cfg = Config::new()
  cfg.host = "resync-\{@env.now()}.test"
  cfg.out_dir = "/tmp"
  let user = "resync@test"
  // No baseline: no mismatch (the record appears with --last/--resync).
  assert_false(uidvalidity_mismatch(cfg, user, "INBOX", 7))
  record_uidvalidity(cfg, user, "INBOX", 42)
  // Same generation: no mismatch.
  assert_false(uidvalidity_mismatch(cfg, user, "INBOX", 42))
  // Changed generation: the predicate that gates --resync recovery.
  assert_true(uidvalidity_mismatch(cfg, user, "INBOX", 43))
  // A '|' in the folder name must not collide across entries (j14 encoding).
  record_uidvalidity(cfg, user, "Work|2024", 7)
  assert_false(uidvalidity_mismatch(cfg, user, "Work|2024", 7))
  assert_true(uidvalidity_mismatch(cfg, user, "Work|2024", 8))
}
