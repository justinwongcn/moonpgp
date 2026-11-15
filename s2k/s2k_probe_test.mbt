// Hacker-round probes (2026-11-13): F3 residual — key_len gate coverage.

///|
/// F3 gated only the Simple/Salted hash branch; Iterated and Argon2 still
/// take an unbounded direct-constructed key_len, so the same
/// million-octet workload F3 closed off is one pub(all) struct away.
test "derive_key rejects outsized key_len on every S2k flavor" {
  let it : @s2k.S2k = @s2k.Iterated(@primitives.Sha256, Bytes::make(8, 0), 96)
  let raised = try {
    let _ = it.derive_key(b"p", 1_000_000)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  let ag : @s2k.S2k = @s2k.Argon2(Bytes::make(8, 0), 1, 8, 1)
  let raised2 = try {
    let _ = ag.derive_key(b"p", 1_000_000)
    false
  } catch {
    _ => true
  }
  assert_true(raised2)
}

///|
/// Control (must stay green): wire-scale key lengths keep working on the
/// gated branch and on Iterated.
test "derive_key accepts wire-scale key lengths" {
  let it : @s2k.S2k = @s2k.Iterated(@primitives.Sha256, Bytes::make(8, 0), 96)
  assert_eq(it.derive_key(b"p", 32).length(), 32)
  let sal : @s2k.S2k = @s2k.Salted(@primitives.Sha256, Bytes::make(8, 0))
  assert_eq(sal.derive_key(b"p", 32).length(), 32)
}
