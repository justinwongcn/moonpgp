///|
/// M5 multi-User-ID tests: gopenpgp's key model carries every certified
/// User ID; ours now does too.

///|
/// GnuPG 2.4.5 key with two User IDs, each with its own Positive
/// certification (generated with `--quick-add-uid`).
test "import a two-User-ID key from GnuPG" {
  let key = @api.PublicKey::from_armored(
    read_testdata("interop_gpg_two_uid_key.asc"),
  )
  // Both User IDs survive the import, in wire order.
  assert_eq(key.user_ids.length(), 2)
  assert_eq(key.user_ids[0].user_id, "First UID <first@test.local>")
  assert_eq(key.user_ids[1].user_id, "Second UID <second@test.local>")
  // The compat accessors point at the first User ID.
  assert_eq(key.user_id(), "First UID <first@test.local>")
  // Byte-stable round trip.
  let again = @api.PublicKey::from_bytes(key.to_bytes().exact_view())
  assert_eq(again.user_ids.length(), 2)
  assert_eq(again.to_bytes(), key.to_bytes())
  // Both certifications verify over the primary key (validated on import;
  // assert the standalone entry point too).
  for b in key.user_ids {
    assert_true(
      @api.verify_key_signature(
        b.self_signature,
        key.primary,
        key.primary,
        user_id=b.user_id,
      ),
    )
  }
}
