///|
/// A User ID revocation signed by a DIFFERENT key must not take effect:
/// `is_user_id_revoked` verifies cryptographically (the lazy model shared
/// with `is_revoked`), so an attacker attaching someone else's revocation
/// signature cannot invalidate an identity they do not control.
test "a foreign-signed user id revocation is ignored" {
  let victim = generate_ed25519_key("X <x@example.com>")
  let attacker = generate_ed25519_key("X <x@example.com>")
  let attackers_revocation = attacker.revoke_user_id("X <x@example.com>").user_ids[0].revocation.unwrap()
  let forged : PublicKey = {
    ..victim.to_public(),
    user_ids: [
      UserIdBinding::{
        user_id: "X <x@example.com>",
        self_signature: victim.to_public().user_ids[0].self_signature,
        revocation: Some(attackers_revocation),
      },
    ],
  }
  assert_false(forged.is_user_id_revoked("X <x@example.com>", 0L))
  // The genuine self-revocation still verifies.
  let genuine = victim.revoke_user_id("X <x@example.com>")
  assert_true(genuine.is_user_id_revoked("X <x@example.com>", 0L))
}
