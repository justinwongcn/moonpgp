///|
/// RFC 9580 Appendix A.9–A.11 complete message sequences: a v6 SKESK
/// followed by a v2 SEIPD packet, passphrase "password", AES-128, and one
/// AEAD mode each (EAX, OCB, GCM). These exercise the whole v6 symmetric
/// path: v6 SKESK parsing, HKDF key separation, AEAD session-key unwrap,
/// v2 SEIPD key/IV derivation, chunked AEAD, and the inner packet walk.

///|
const A9_EAX_MESSAGE : String =
  #|-----BEGIN PGP MESSAGE-----
  #|
  #|w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14
  #|KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq
  #|pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1
  #|QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=
  #|-----END PGP MESSAGE-----

///|
const A10_OCB_MESSAGE : String =
  #|-----BEGIN PGP MESSAGE-----
  #|
  #|wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl
  #|ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM
  #|WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0
  #|K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==
  #|-----END PGP MESSAGE-----

///|
const A11_GCM_MESSAGE : String =
  #|-----BEGIN PGP MESSAGE-----
  #|
  #|wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa
  #|v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax
  #|Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS
  #|+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==
  #|-----END PGP MESSAGE-----

///|
test "decrypt RFC 9580 A.9.5 v6 SKESK + v2 SEIPD with EAX" {
  assert_eq(
    @api.decrypt_with_password(A9_EAX_MESSAGE, "password"),
    @primitives.utf8_bytes("Hello, world!"),
  )
}

///|
test "decrypt RFC 9580 A.10.5 v6 SKESK + v2 SEIPD with OCB" {
  assert_eq(
    @api.decrypt_with_password(A10_OCB_MESSAGE, "password"),
    @primitives.utf8_bytes("Hello, world!"),
  )
}

///|
test "decrypt RFC 9580 A.11.5 v6 SKESK + v2 SEIPD with GCM" {
  assert_eq(
    @api.decrypt_with_password(A11_GCM_MESSAGE, "password"),
    @primitives.utf8_bytes("Hello, world!"),
  )
}

///|
test "v6 SKESK + v2 SEIPD reject the wrong passphrase" {
  let raised = try {
    ignore(@api.decrypt_with_password(A10_OCB_MESSAGE, "wrong"))
    false
  } catch {
    @error.PgpError(msg~) => {
      assert_true(msg.contains("tag mismatch"))
      true
    }
    _ => fail("expected a PgpError from the AEAD tag check")
  }
  assert_true(raised)
}

///|
test "v2 SEIPD tampering is rejected (chunked AEAD tag)" {
  // Flip one octet of the A.10.5 packet stream after de-armoring and
  // re-armoring; the chunk AEAD tag must reject it.
  let block = @armor.decode(A10_OCB_MESSAGE)
  let data = block.data().to_array()
  // The SKESK is 2 + 0x3f = 65 octets; tamper inside the SEIPD ciphertext.
  data[80] = (data[80].to_int() ^ 0x01).to_byte()
  let tampered = @armor.Message.encode(Bytes::from_array(data).exact_view())
  let raised = try {
    ignore(@api.decrypt_with_password(tampered, "password"))
    false
  } catch {
    @error.PgpError(msg~) => {
      assert_true(msg.contains("SEIPD v2"))
      true
    }
    _ => fail("expected the v2 SEIPD tag check to reject the tampering")
  }
  assert_true(raised)
}

///|
/// RFC 9580 Appendix A.4: the unprotected v6 transferable secret key
/// (Ed25519 primary + X25519 subkey) whose locked form is A.5.
const A4_ARMORED : String =
  #|-----BEGIN PGP PRIVATE KEY BLOCK-----
  #|
  #|xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
  #|exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
  #|BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
  #|2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
  #|RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
  #|7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
  #|LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
  #|GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
  #|2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
  #|M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
  #|k0mXubZvyl4GBg==
  #|-----END PGP PRIVATE KEY BLOCK-----

///|
/// RFC 9580 Appendix A.8.5: the complete X25519 + AEAD-OCB message.
const A8_OCB_MESSAGE : String =
  #|-----BEGIN PGP MESSAGE-----
  #|
  #|wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO
  #|WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS
  #|aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l
  #|yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo
  #|bhF30A+IitsxxA==
  #|-----END PGP MESSAGE-----

///|
test "decrypt RFC 9580 A.8.5 X25519 + v6 PKESK + v2 SEIPD (OCB)" {
  let key = @api.PrivateKey::from_armored(A4_ARMORED)
  assert_eq(key.primary.public.version(), 6)
  assert_eq(key.primary.public.algo(), @packet.Ed25519)
  let subkey = key.subkeys[0].secret
  assert_eq(subkey.public.version(), 6)
  assert_eq(subkey.public.algo(), @packet.X25519)
  assert_eq(
    @api.decrypt_with_private_key(A8_OCB_MESSAGE, key),
    @primitives.utf8_bytes("Hello, world!"),
  )
}

///|
test "v6 key generation round trips through armor and encryption" {
  let key = @api.generate_ed25519_v6_key("V6 Round Trip <v6rt@example.com>")
  let subkey = key.subkeys[0].secret
  assert_eq(subkey.public.version(), 6)
  assert_eq(subkey.public.algo(), @packet.X25519)
  // The public half must stay usable after an armor round trip.
  let reimported = @api.PrivateKey::from_armored(key.to_armored())
  assert_eq(reimported.fingerprint(), key.fingerprint())
  let message = @api.encrypt_to_recipients(
    @primitives.utf8_bytes("v6 message round trip\n"),
    [key.to_public()],
  )
  assert_eq(
    @api.decrypt_with_private_key(message, key),
    @primitives.utf8_bytes("v6 message round trip\n"),
  )
}

///|
test "a v6 inline signature carries a v6 One-Pass Signature packet" {
  let key = @api.generate_ed25519_v6_key("V6 Sign <v6s@example.com>")
  let data = @primitives.utf8_bytes("inline v6\n")
  let message = @api.sign_inline(data, key)
  let packets = @packet.parse_packets(
    @armor.decode(message).data().exact_view(),
  )
  assert_eq(packets[0].tag(), @packet.OnePassSig)
  let ops = @packet.OnePassSigPacket::parse(packets[0].body().exact_view())
  assert_eq(ops.version(), 6)
  // RFC 9580 Table 23: the SHA2-256 signature salt is 16 octets.
  assert_eq(ops.salt().length(), 16)
  let sig = @packet.SignaturePacket::parse(
    packets[packets.length() - 1].body().exact_view(),
  )
  // RFC 9580 §5.4: the OPS salt must equal the signature's salt.
  assert_eq(ops.salt(), sig.salt())
  let (text, status) = @api.verify_inline(message, key.to_public())
  assert_eq(text, data)
  assert_eq(status, @api.VerifyStatus::Ok)
}

///|
test "v6 passphrase encryption round trips for every AEAD mode" {
  for mode in [@cipher.Ocb, @cipher.Eax, @cipher.Gcm] {
    let plaintext = @primitives.utf8_bytes("v6 " + mode_label(mode) + "\n")
    // Iterated S2K keeps this cheap; Argon2 is covered separately.
    let message = @api.encrypt_with_password_v6(
      plaintext,
      "v6-passphrase",
      aead=mode,
      argon2=false,
    )
    assert_eq(
      @api.decrypt_with_password(message, "v6-passphrase"),
      plaintext,
      msg="mode " + mode_label(mode),
    )
  }
}

///|
test "v6 passphrase encryption with Argon2 round trips" {
  let plaintext = @primitives.utf8_bytes("v6 argon2\n")
  let message = @api.encrypt_with_password_v6(
    plaintext,
    "v6-argon2",
    passes=1,
    parallelism=1,
    memory_exp=5,
  )
  // The SKESK really is a v6 packet with an Argon2 specifier.
  let packets = @packet.parse_packets(
    @armor.decode(message).data().exact_view(),
  )
  let skesk = @packet.SkeskPacket::parse(packets[0].body().exact_view())
  assert_eq(skesk.version(), 6)
  assert_true(skesk.s2k().is_argon2())
  assert_eq(@api.decrypt_with_password(message, "v6-argon2"), plaintext)
}

///|
fn mode_label(mode : @cipher.AeadMode) -> String {
  match mode {
    @cipher.Ocb => "ocb"
    @cipher.Eax => "eax"
    @cipher.Gcm => "gcm"
  }
}

///|
test "the Argon2 memory policy is enforced before allocating" {
  // A passphrase message whose Argon2 specifier asks for more than the
  // caller's ceiling must be refused, not allocated.
  let message = @api.encrypt_with_password_argon2(
    @primitives.utf8_bytes("policy"),
    "pw",
    passes=1,
    parallelism=1,
    memory_exp=10,
  )
  // 2^10 KiB is fine at the default ceiling...
  assert_eq(
    @api.decrypt_with_password(message, "pw", argon2_max_memory_kib=1024),
    @primitives.utf8_bytes("policy"),
  )
  // ...and refused under a tighter one.
  let raised = try {
    ignore(@api.decrypt_with_password(message, "pw", argon2_max_memory_kib=64))
    false
  } catch {
    @error.PgpError(msg~) => {
      assert_true(msg.contains("exceeds the cap"))
      true
    }
    _ => fail("expected a PgpError from the Argon2 memory cap")
  }
  assert_true(raised)
}

///|
test "the secret-key Argon2 memory policy is enforced" {
  let key = @api.generate_key("Policy <p@example.com>", bits=2048).lock_argon2(
    "pw",
    passes=1,
    parallelism=1,
    memory_exp=6,
  )
  // 2^6 KiB fits under a 64 KiB ceiling.
  assert_eq(
    key.unlock("pw", argon2_max_memory_kib=64).fingerprint(),
    key.fingerprint(),
  )
  let raised = try {
    ignore(key.unlock("pw", argon2_max_memory_kib=32))
    false
  } catch {
    @error.PgpError(msg~) => {
      assert_true(msg.contains("exceeds the cap"))
      true
    }
    _ => fail("expected a PgpError from the Argon2 memory cap")
  }
  assert_true(raised)
}

///|
test "v5 SKESK can use Argon2 and still round trips" {
  let plaintext = @primitives.utf8_bytes("v5 argon2\n")
  let message = @api.encrypt_with_password(
    plaintext,
    "v5-argon2",
    aead=true,
    argon2=true,
    argon2_memory_exp=5,
  )
  let packets = @packet.parse_packets(
    @armor.decode(message).data().exact_view(),
  )
  let skesk = @packet.SkeskPacket::parse(packets[0].body().exact_view())
  assert_eq(skesk.version(), 5)
  assert_true(skesk.s2k().is_argon2())
  assert_eq(@api.decrypt_with_password(message, "v5-argon2"), plaintext)
}

///|
test "v6 keys advertise v2 SEIPD and their AEAD preferences" {
  let key = @api.generate_ed25519_v6_key("Prefs <prefs@example.com>")
  assert_true(key.to_public().supports_seipd_v2())
  assert_eq(key.to_public().preferred_aead(), [(9, 2), (9, 3), (7, 2)])
  // v4 keys keep the old Features octet and advertise no AEAD list.
  let v4 = @api.generate_key("V4 <v4@example.com>", bits=2048)
  assert_false(v4.to_public().supports_seipd_v2())
  assert_eq(v4.to_public().preferred_aead().length(), 0)
}
