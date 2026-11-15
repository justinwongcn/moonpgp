// Hacker-round probes (2026-11-13), s2k facet: parameter gates.

///|
/// validate_argon2 only demands passes != 0 and parallelism != 0: a
/// direct-constructed negative t sails through into charge_argon2 (api
/// layer) and turns the budget counter negative, disabling the Iterated
/// S2K work ceiling for the rest of the message.
test "validate_argon2 requires positive passes and parallelism" {
  let raised_t = try {
    validate_argon2(-1, 1, 20)
    false
  } catch {
    _ => true
  }
  assert_true(raised_t)
  let raised_p = try {
    validate_argon2(1, -3, 20)
    false
  } catch {
    _ => true
  }
  assert_true(raised_p)
  validate_argon2(1, 1, 20)
}
