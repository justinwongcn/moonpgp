///|
/// RFC 9106 §5.3 known-answer test for Argon2id, including the optional
/// 8-octet secret K and 12-octet associated data X. This is the vector the
/// RFC itself publishes; the intermediate block values live in the
/// white-box test file so a regression can be localized.
test "argon2id RFC 9106 §5.3 KAT (t=3, m=32 KiB, p=4, T=32, with K and X)" {
  let tag = @primitives.argon2id_with_secret_ad(
    Bytes::make(32, b'\x01'),
    Bytes::make(16, b'\x02'),
    Bytes::make(8, b'\x03'),
    Bytes::make(12, b'\x04'),
    3,
    32,
    4,
    32,
  )
  assert_eq(
    @primitives.to_hex(tag),
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
  )
}

///|
/// Argon2id vectors from `golang.org/x/crypto/argon2`'s test suite
/// (research brief §4.2): password "password", salt "somesalt", **24-octet**
/// tags, no secret or associated data. (The brief's header says "16 bytes";
/// the listed hex strings are 48 characters, i.e. 24 octets. Re-verified
/// against `golang.org/x/crypto v0.41.0`.)
test "argon2id x/crypto vectors" {
  let pass = b"password"
  let salt = b"somesalt"
  let cases : Array[(Int, Int, Int, String)] = [
    (1, 64, 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"),
    (2, 64, 1, "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"),
    (2, 64, 2, "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"),
    (3, 256, 2, "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"),
    (4, 4096, 4, "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a"),
    (4, 1024, 8, "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f"),
    (2, 64, 3, "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"),
    (3, 1024, 6, "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016"),
  ]
  for c in cases {
    let (passes, m_kib, parallelism, want) = c
    let tag = @primitives.argon2id(pass, salt, passes, m_kib, parallelism, 24)
    assert_eq(
      @primitives.to_hex(tag),
      want,
      msg="t=\{passes} m=\{m_kib} p=\{parallelism}",
    )
  }
}

///|
test "argon2id rejects parameters outside the RFC 9106 domain" {
  let pass = b"pw"
  let salt = b"salt"
  // passes == 0
  assert_argon2_raises(pass, salt, 0, 64, 1, 16)
  // parallelism == 0
  assert_argon2_raises(pass, salt, 1, 64, 0, 16)
  // tag length == 0
  assert_argon2_raises(pass, salt, 1, 64, 1, 0)
  // m < 8*p
  assert_argon2_raises(pass, salt, 1, 8, 2, 16)
  // above the caller's ceiling
  assert_argon2_raises(pass, salt, 1, 64, 1, 16, max_memory_kib=32)
  // above the implementation ceiling
  assert_argon2_raises(pass, salt, 1, ARGON2_OVER_LIMIT_KIB, 1, 16)
}

///|
test "argon2id memory cap is a policy knob, not a correctness change" {
  // A tighter cap must not change the result when it is respected.
  let capped = @primitives.argon2id(
    b"password",
    b"somesalt",
    1,
    64,
    1,
    16,
    max_memory_kib=64,
  )
  let open = @primitives.argon2id(b"password", b"somesalt", 1, 64, 1, 16)
  assert_eq(capped, open)
}

///|
/// One KiB above the hard ceiling: the call must fail before allocating.
const ARGON2_OVER_LIMIT_KIB : Int = @primitives.ARGON2_MAX_MEMORY_KIB + 1024

///|
fn assert_argon2_raises(
  pass : BytesView,
  salt : BytesView,
  passes : Int,
  m_kib : Int,
  parallelism : Int,
  tag_len : Int,
  max_memory_kib? : Int = @primitives.ARGON2_MAX_MEMORY_KIB,
) -> Unit raise {
  // The old shape put `fail(...)` INSIDE the `try`, so the `catch` swallowed
  // it and the helper could never fail: a call that wrongly succeeded passed.
  let raised = try {
    ignore(
      @primitives.argon2id(
        pass,
        salt,
        passes,
        m_kib,
        parallelism,
        tag_len,
        max_memory_kib~,
      ),
    )
    false
  } catch {
    @error.PgpError(msg~) => {
      assert_true(msg.has_prefix("argon2:"))
      true
    }
    _ => fail("expected a PgpError from the Argon2 validation guards")
  }
  assert_true(
    raised,
    msg="argon2id(passes=\{passes}, m=\{m_kib}, p=\{parallelism}, T=\{tag_len}, cap=\{max_memory_kib}) must raise",
  )
}

///|
/// go-crypto v1.4.1 `openpgp/s2k/s2k_test.go` `argon2DeriveTests`: an
/// 8-octet ASCII salt "12345678" with t=3, p=4, m=64 MiB, and the tag
/// length implied by each expected value (re-verified against
/// `golang.org/x/crypto/argon2 v0.41.0`). OpenPGP itself always uses a
/// 16-octet salt; this pins the raw derivation.
test "argon2id go-crypto S2K derive vectors (8-octet salt)" {
  let salt = b"12345678"
  let cases : Array[(String, String)] = [
    ("hello", "bf69293d2961bbbebe4c64c745cf44d4"),
    ("world", "dc1bb06234b61c9542d8cf73e2e279d3"),
    ("foo", "7f6baa1c21f0e7eec16cf8fde866775d"),
    ("bar", "2826332c8e62d0cf97cc08f243c5cc9135654bf3a8e46d6a4b4637e42eda2fa0"),
    ("x", "89e5b79435132b98bbcad321532ae7e09f87ac96deca272d6012d367e6350b7d"),
    (
      "xxxxxxxxxxxxxxxxxxxxxxx", "de0f978013283457e29f0682e0078ad654e7c21bc72886c914c012e56fd5dc91",
    ),
  ]
  for c in cases {
    let (pass, want) = c
    let tag_len = want.length() / 2
    let tag = @primitives.argon2id(
      @primitives.utf8_bytes(pass),
      salt,
      3,
      64 * 1024,
      4,
      tag_len,
    )
    assert_eq(@primitives.to_hex(tag), want, msg="passphrase \{pass}")
  }
}

///|
/// Additional `golang.org/x/crypto/argon2 v0.41.0` vectors chosen to cover
/// the paths the RFC KAT does not: memory sizes that are not a multiple of
/// `4*parallelism` (exercising the `m'` rounding of RFC 9106 §3.1),
/// parallelism values other than 4, and tag lengths above 64 octets (the
/// H' chaining path).
test "argon2id x/crypto vectors: m' rounding, odd p, long tags" {
  let pass = b"password"
  let salt = b"somesalt"
  let cases : Array[(Int, Int, Int, Int, String)] = [
    (1, 100, 3, 16, "b9c657c11e03699ee8c9d0cda5d6b03a"),
    (2, 1000, 7, 16, "1aba3309d95e2fd00812355df499ce8a"),
    (3, 33, 1, 16, "40d1b39ac2dc92fc54ca64e802860dfe"),
    (
      2, 96, 3, 64, "2b24dfd5412a4f69c9fc8ba281580512db1d812fbf8495900d5dfbb341d70188745ed409b2bdc7c000b38b8cffebb1958f1c7eefcea8d2264124b7986afeb2cd",
    ),
    (
      1, 512, 2, 100, "1d7be4556089755ddf643fa1c5ffdf6b65594caa5538876c38a536767adb16228ed3fed6362ad4884e4477122fbb69be1bf0ca56b1f7b18864b14354abd4a561ea158027e4fdd4f50d67b4642f6aa98fb661a16e56963a48e92decc5f1dd077711eb4a0a",
    ),
    (
      2, 2048, 4, 128, "8ec0c2e6f6cd019884427b885110efcb128183fb97e58d4f38762f72e133461fba4bf0bd1f160a2d133dcfb294612da27eb638850aa36c11eeb541df73999bb91cbd1e67d9befc4ef54ed79ac5e4cc1b5b7b9764859bcc4c45e93ef5502c03767c87e81d654e04342218ad673f22c02b6ea3e76408aa72309d74628046f7efb4",
    ),
    (
      1, 32, 4, 64, "2b32c78bb3ad111f15c38c598e9e032a7619074456e7477c2115160055cdb90600672005ce4f7c22864e3b89b693e2216beb31d2ad64c6a9cb980af1d1cc9d38",
    ),
  ]
  for c in cases {
    let (passes, m_kib, parallelism, tag_len, want) = c
    let tag = @primitives.argon2id(
      pass, salt, passes, m_kib, parallelism, tag_len,
    )
    assert_eq(
      @primitives.to_hex(tag),
      want,
      msg="t=\{passes} m=\{m_kib} p=\{parallelism} T=\{tag_len}",
    )
  }
}
