///|
/// Argon2 S2K (RFC 9580 §3.7.1.4) end-to-end and self-round-trip tests.
///
/// The cheap default cases use a 32 KiB Argon2 memory (encoded_m = 5); the
/// RFC 9580 Appendix A.12/A.5 fixtures hard-code the RFC's first recommended
/// option m = 2^21 KiB (2 GiB) and are marked `#skip`, because each
/// derivation allocates 2 GiB and takes ~15 s in a debug build. Run them
/// with:
///
///   moon test src/api --target native --include-skipped --filter "slow:*"

///|
/// A v4 SKESK + v1 SEIPD message with an Argon2 S2K round-trips through the
/// public passphrase API.
test "argon2 SKESK passphrase round trip" {
  let plaintext = @primitives.utf8_bytes("argon2 s2k round trip 中文\n")
  let message = @api.encrypt_with_password_argon2(
    plaintext,
    "correct horse battery staple",
    passes=1,
    parallelism=1,
    memory_exp=5,
  )
  // The S2K specifier really is type 4.
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(block.data().exact_view())
  let skesk = @packet.SkeskPacket::parse(packets[0].body().exact_view())
  assert_true(skesk.s2k().is_argon2())
  assert_eq(
    plaintext,
    @api.decrypt_with_password(message, "correct horse battery staple"),
  )
}

///|
/// `encrypt_with_password(..., argon2=true)` must select the Argon2id
/// specifier even in the v4 SKESK shape. The flag used to be honoured only
/// in the `aead=true` branch, so asking for Argon2 silently produced
/// iterated SHA-256 — a KDF downgrade with no error.
test "encrypt_with_password honors argon2 in the v4 SKESK shape" {
  let plaintext = @primitives.utf8_bytes("argon2 via the v4 skesk flag\n")
  let message = @api.encrypt_with_password(
    plaintext,
    "correct horse battery staple",
    argon2=true,
    argon2_memory_exp=5,
  )
  let block = @armor.decode(message)
  let packets = @packet.parse_packets(block.data().exact_view())
  let skesk = @packet.SkeskPacket::parse(packets[0].body().exact_view())
  assert_eq(skesk.version(), 4)
  assert_true(skesk.s2k().is_argon2())
  assert_eq(
    plaintext,
    @api.decrypt_with_password(message, "correct horse battery staple"),
  )
}

///|
/// The wrong passphrase must fail (the CFB unwrap yields a session key whose
/// length or SEIPD MDC does not check out).
test "argon2 SKESK rejects the wrong passphrase" {
  let message = @api.encrypt_with_password_argon2(
    @primitives.utf8_bytes("secret"),
    "right",
    passes=1,
    parallelism=1,
    memory_exp=5,
  )
  let raised = try {
    ignore(@api.decrypt_with_password(message, "wrong"))
    false
  } catch {
    @error.PgpError(msg~) => {
      // Either the garbage session key fails the SEIPD layer or its cipher
      // octet is not a known algorithm; both are controlled failures.
      assert_true(msg.contains("seipd:") || msg.contains("api:"))
      true
    }
    _ => fail("expected a PgpError for the wrong passphrase")
  }
  assert_true(raised)
}

///|
/// A key locked with Argon2id + AES-256/OCB (usage 253) unlocks again, and
/// the packet really carries the AEAD protection.
test "argon2 AEAD secret key lock/unlock round trip" {
  let key = @api.generate_key("Argon2 <a2@example.com>", bits=1024)
  let locked = key.lock_argon2(
    "passphrase",
    passes=1,
    parallelism=1,
    memory_exp=5,
  )
  assert_true(locked.is_locked())
  assert_true(locked.is_aead_protected())
  assert_eq(locked.primary.s2k_usage, 253)
  assert_eq(locked.primary.aead_algo, @cipher.Ocb.number())
  // The wire form round-trips through armor/parse and still unlocks.
  let reimported = @api.PrivateKey::from_armored(locked.to_armored())
  assert_true(reimported.is_aead_protected())
  assert_eq(
    reimported.unlock("passphrase").to_public().to_armored(),
    key.to_public().to_armored(),
  )
}

///|
/// Argon2 must be refused with the CFB usage octets (RFC 9580 §3.7.2.1: an
/// implementation MUST reject Argon2 without AEAD).
test "argon2 specifier is rejected with S2K usage 254/255" {
  let salt = Bytes::make(@s2k.ARGON2_SALT_SIZE, b'\x01')
  let spec = @s2k.Argon2(salt, 1, 1, 5).encode()
  let public = @api.generate_key("X <x@example.com>", bits=1024).primary.public
  for usage in [254, 255] {
    let key : @packet.SecretKeyPacket = {
      public,
      s2k_usage: usage,
      cipher_algo: 9,
      aead_algo: 0,
      s2k_spec: spec,
      iv: Bytes::make(16, b'\x00'),
      secret_material: Bytes::make(16, b'\x00'),
      dummy: false,
    }
    let raised = try {
      ignore(@packet.SecretKeyPacket::parse(key.to_body().exact_view()))
      false
    } catch {
      @error.PgpError(msg~) => {
        assert_true(msg.contains("without AEAD"))
        true
      }
      _ => fail("expected a PgpError for Argon2 without AEAD")
    }
    assert_true(raised, msg="usage \{usage} must reject Argon2")
  }
}

///|
/// RFC 9580 Appendix A.12: three complete S2K-encrypted session key +
/// SEIPD v1 messages, passphrase "password", plaintext "Hello, world!".
/// The brief's §4.5 tables give the expected Argon2 KEK and unwrapped
/// session key for each.
///
/// A.12.1 is AES-128, A.12.2 AES-192 and A.12.3 AES-256: the message cipher
/// comes from the octet wrapped inside the SKESK, not from the SKESK's own
/// wrapping cipher.
#skip("2 GiB Argon2 per sample; run with --include-skipped --filter 'slow:*'")
test "slow: RFC 9580 A.12 SKESK Argon2 messages decrypt to Hello, world!" {
  let samples : Array[String] = [
    // A.12.1 (AES-128, sha256 59015ef8…b765)
    "c3270407049c52f83c27f95e50d535440ecdff31360104159e52fcad22cf3f956542cba794ef840b11d23e019818a63e609cf8bba17e0c394304eaf9351417b7f28921fe26e263a52b20bfbaa2dba672c964c9d3ab7a3bf46c414dd21d3b38475df037a6a578993cc5",
    // A.12.2 (AES-192, sha256 e7eee1bc…272d5c)
     "c32f040804e14cac4715345918a962dca347e143f80104158732c9daf6b7146f3fa66a483ddfc7fe6768552e5504b2f017d23e01d2754b0e7a3d16222998c2bc783ed9b9ead36b37dc0249a3205ec4123840a0131519327b3da095d265751cac2d583beccc307e09769ff779ef659c8803",
    // A.12.3 (AES-256, sha256 97b4f272…5a2c32)
     "c337040904b8789520206ff799c6882c4245a6627c0104159d9f65ecab5a81d0a59bd51a43f67a33fe6ba249521a91aeeb6dd899a5decc68fcd23e01f8abb5b204dd268f3b5f55abba9ee5d30272a5996cdb553077aee6f64a05eb479e7c7fcaf790f5bac9625ce126f1ac90250999ae37fa2babfd3d6c2a31",
  ]
  for i, hex in samples {
    let message = @primitives.from_hex(hex)
    assert_eq(
      // RFC 9106's first recommended option is 2 GiB, above the 256 MiB
      // default policy, so these samples widen it explicitly.
      @api.decrypt_binary_with_password(
        message.exact_view(),
        "password",
        argon2_max_memory_kib=@primitives.ARGON2_MAX_MEMORY_KIB,
      ),
      @primitives.utf8_bytes("Hello, world!"),
      msg="A.12.\{i + 1}",
    )
  }
}

///|
/// RFC 9580 Appendix A.5: the locked v6 Ed25519 primary key plus X25519
/// subkey, AEAD (OCB) + Argon2 S2K, passphrase "correct horse battery
/// staple". Unlocking must expose a usable secret key.
#skip("2 GiB Argon2 per key packet; run with --include-skipped --filter 'slow:*'")
test "slow: RFC 9580 A.5 v6 secret key unlocks (Argon2 + OCB + HKDF)" {
  let key = @api.PrivateKey::from_armored(A5_ARMORED)
  assert_true(key.is_locked())
  assert_true(key.is_aead_protected())
  // A.5 uses the RFC's 2 GiB Argon2 option: widen the default policy.
  let unlocked = key.unlock(
    "correct horse battery staple",
    argon2_max_memory_kib=@primitives.ARGON2_MAX_MEMORY_KIB,
  )
  assert_false(unlocked.is_locked())
  // The primary and subkey fingerprints are unchanged by unlocking; a
  // missing tag check would have produced a different secret payload.
  assert_eq(unlocked.fingerprint(), key.fingerprint())
  assert_eq(
    unlocked.primary.secret_material.length(),
    32,
    msg="v6 Ed25519 secret material is the 32-octet scalar (RFC 9580 §5.5.5.9)",
  )
  // The decrypted scalar is usable: a detached signature verifies.
  let data = @primitives.utf8_bytes("unlocked from RFC 9580 A.5")
  let sig = @api.sign_detached(data, unlocked)
  assert_eq(
    @api.verify_detached(data, sig, unlocked.to_public()),
    @api.VerifyStatus::Ok,
  )
  // The wrong passphrase must not authenticate.
  let raised = try {
    ignore(
      key.unlock(
        "wrong passphrase",
        argon2_max_memory_kib=@primitives.ARGON2_MAX_MEMORY_KIB,
      ),
    )
    false
  } catch {
    @error.PgpError(msg~) => {
      assert_true(msg.contains("wrong passphrase"))
      true
    }
    _ => fail("expected a PgpError from the AEAD tag check")
  }
  assert_true(raised, msg="AEAD tag must reject a wrong passphrase")
}

///|
/// The RFC 9580 Appendix A.5 private key block, verbatim.
const A5_ARMORED : String =
  #|-----BEGIN PGP PRIVATE KEY BLOCK-----
  #|
  #|xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC
  #|FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS
  #|3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC
  #|Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW
  #|cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin
  #|7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/
  #|0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0
  #|gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf
  #|9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR
  #|v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr
  #|DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki
  #|Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt
  #|ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG
  #|-----END PGP PRIVATE KEY BLOCK-----

///|
/// A v6 usage-253 packet must carry the two count octets of RFC 9580
/// §5.5.3 in the right places: the cumulative S2K-parameter count right
/// after the usage octet (cipher + AEAD + S2K-length + S2K + IV), and the
/// S2K-specifier length before the specifier.
test "v6 usage-253 secret key writes the RFC 9580 parameter counts" {
  let key = @api.generate_ed25519_v6_key("V6 <v6@example.com>").lock_argon2(
    "pw",
    passes=1,
    parallelism=1,
    memory_exp=5,
  )
  let body = key.primary.to_body()
  let pub_len = key.primary.public.to_body().length()
  assert_eq(body[pub_len].to_int(), 253)
  // 1 cipher + 1 AEAD + 1 spec-length + 20-octet Argon2 spec + 15-octet OCB nonce.
  assert_eq(body[pub_len + 1].to_int(), 38)
  let parsed = @packet.SecretKeyPacket::parse(body.exact_view())
  assert_true(@s2k.parse(parsed.s2k_spec.exact_view()).0.is_argon2())
  assert_eq(parsed.s2k_spec.length(), 20)
  assert_eq(parsed.aead_algo, @cipher.Ocb.number())
  assert_eq(parsed.iv.length(), @cipher.Ocb.iv_length())
  // Re-serializing reproduces the same layout byte for byte.
  assert_eq(parsed.to_body(), body)
}

///|
/// A v4 SKESK carrying an Argon2 S2K with the given encoded memory exponent
/// and a bogus wrapped session key. Built by hand (no KDF is run) so a test
/// can hand the decoder a 2 GiB request while staying cheap itself.
fn argon2_skesk_with_memory(memory_exp : Int) -> Bytes {
  let body = @packet.Writer::new()
  body.u8(4) // SKESK v4
  body.u8(@primitives.Aes256.number())
  body.u8(4) // S2K type 4 = Argon2id
  body.bytes(Bytes::make(16, b'\x11').exact_view()) // salt
  body.u8(1) // t
  body.u8(1) // p
  body.u8(memory_exp) // encoded_m
  body.bytes(Bytes::make(48, b'\x22').exact_view()) // ESK placeholder
  @packet.serialize_packet(@packet.Skesk, body.to_bytes().exact_view())
}

///|
/// The S2K parameters are attacker-controlled and the derivation runs before
/// any authentication, so the *default* 256 MiB policy must refuse a 2 GiB
/// request before allocating anything. (The packet is built by hand, so this
/// test never allocates the 2 GiB it is refusing.)
test "the default Argon2 memory policy refuses a 2 GiB request" {
  let wire = argon2_skesk_with_memory(21)
  try @api.decrypt_binary_with_password(wire, "pw") catch {
    @error.PgpError(msg~) => {
      assert_true(msg.contains("exceeds the cap"))
      assert_true(msg.contains("262144"))
    }
    _ => fail("expected a PgpError for the oversized request")
  } noraise {
    _ => fail("a 2 GiB Argon2 S2K was accepted under the default policy")
  }
}

///|
/// The cap is a caller-visible policy: a 1 MiB request passes the default
/// 256 MiB policy (what fails afterwards is the bogus wrapped session key),
/// while an explicit 512 KiB cap stops the very same packet. Widening beyond
/// the default is what the RFC Appendix A.5/A.12 `slow:*` vectors do.
test "an explicit Argon2 memory cap is enforced before allocating" {
  let wire = argon2_skesk_with_memory(10) // 2^10 KiB = 1 MiB
  try @api.decrypt_binary_with_password(wire, "pw") catch {
    @error.PgpError(msg~) => assert_false(msg.contains("exceeds the cap"))
    _ => fail("expected a PgpError for the bogus session key")
  } noraise {
    _ => fail("the bogus session key must still be rejected")
  }
  try
    @api.decrypt_binary_with_password(wire, "pw", argon2_max_memory_kib=512)
  catch {
    @error.PgpError(msg~) => assert_true(msg.contains("exceeds the cap"))
    _ => fail("expected a PgpError from the explicit cap")
  } noraise {
    _ => fail("an explicit 512 KiB cap must reject a 1 MiB request")
  }
}
