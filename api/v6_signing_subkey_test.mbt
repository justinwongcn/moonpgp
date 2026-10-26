///|
/// W1: `generate_ed25519_v6_key_with_signing_subkey` produces the gpg
/// dual-subkey shape on a v6 certificate — a cert-only primary, an
/// X25519 encryption subkey and an Ed25519 signing subkey whose v6
/// binding embeds a v6 Primary Key Binding (cross-certification, RFC
/// 9580 §5.2.3.26). This is the first public path that reaches the v6
/// embedded-signature branch end to end.
test "v6 dual-subkey generation: shape, flags and v6 embedded binding" {
  let key = @api.generate_ed25519_v6_key_with_signing_subkey(
    "Dual V6 <dualv6@example.com>",
  )
  // Cert-only v6 primary: the self-signature carries certify-only flags.
  guard key.primary.public.version() == 6 else {
    abort("primary is not a v6 key")
  }
  let flags = key.self_signature().key_flags()
  guard flags is Some(f) && f.length() == 1 && f[0].to_int() == 0x01 else {
    abort("primary self-signature is not certify-only (0x01)")
  }
  // A v6 certificate requires the Direct Key signature, and the
  // encryption subkey's own binding must be a verifying v6 binding.
  guard key.direct_signature is Some(d) else {
    abort("v6 key lacks the Direct Key signature")
  }
  guard d.sig_type() == @packet.DirectSignature else {
    abort("the direct signature has the wrong type")
  }
  // Two v6 subkeys in wire order: encryption (X25519), signing (Ed25519).
  guard key.subkeys.length() == 2 else { abort("expected two subkeys") }
  let enc = key.subkeys[0]
  let sign = key.subkeys[1]
  guard enc.secret.public.version() == 6 else {
    abort("encryption subkey is not v6")
  }
  guard enc.secret.public.algo() == @packet.X25519 else {
    abort("encryption subkey is not X25519")
  }
  guard sign.secret.public.version() == 6 else {
    abort("signing subkey is not v6")
  }
  guard sign.secret.public.algo() == @packet.Ed25519 else {
    abort("signing subkey is not Ed25519")
  }
  guard @api.verify_key_signature(
    enc.binding,
    key.primary.public,
    enc.secret.public,
  ) else {
    abort("encryption subkey binding does not verify")
  }
  // The signing subkey's binding embeds a v6 PrimaryKeyBinding that
  // verifies over (primary, subkey) with the subkey as signer.
  let embedded_body = @packet.find_subpacket(
    sign.binding.unhashed_subpackets,
    @packet.SIGSUB_EMBEDDED_SIGNATURE,
  )
  guard embedded_body is Some(body) else {
    abort("signing subkey binding carries no embedded signature")
  }
  let embedded = @packet.SignaturePacket::parse(body.exact_view())
  guard embedded.sig_type() == @packet.PrimaryKeyBinding else {
    abort("embedded signature is not a PrimaryKeyBinding")
  }
  guard embedded.version() == 6 else { abort("embedded signature is not v6") }
  // A v6 signature names its issuer in the hashed area (§5.2.3.35): the
  // embedded binding must carry the SUBKEY's fingerprint with a version
  // octet matching its own version.
  let embedded_issuer = @packet.find_subpacket(
    embedded.hashed_subpackets,
    @packet.SIGSUB_ISSUER_FINGERPRINT,
  )
  guard embedded_issuer is Some(b) && b.length() == 33 else {
    abort("embedded signature lacks a 32-octet issuer fingerprint")
  }
  guard b[0].to_int() == 6 else {
    abort("embedded issuer fingerprint version octet is not 6")
  }
  assert_eq(b.exact_view()[1:].to_owned(), sign.secret.public.fingerprint())
  guard @api.verify_key_signature(
    embedded,
    sign.secret.public,
    key.primary.public,
  ) else {
    abort("embedded PrimaryKeyBinding does not verify")
  }
}

///|
/// With a cert-only primary the document signature must be issued by the
/// signing subkey: the detached signature's v6 Issuer Fingerprint names
/// the subkey, not the primary, and the public half verifies it.
test "v6 dual-subkey key signs through its signing subkey" {
  let key = @api.generate_ed25519_v6_key_with_signing_subkey(
    "Dual V6 <dualv6@example.com>",
  )
  let sign = key.subkeys[1]
  let data = @primitives.utf8_bytes("signed by the v6 signing subkey\n")
  let sig = @api.sign_detached(data, key)
  let block = @armor.decode(sig)
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut issuer : Bytes = Bytes::new(0)
  for p in packets {
    if p.tag() == @packet.Signature {
      let s = @packet.SignaturePacket::parse(p.body().exact_view())
      let fp = @packet.find_subpacket(
        s.hashed_subpackets,
        @packet.SIGSUB_ISSUER_FINGERPRINT,
      )
      guard fp is Some(b) else {
        abort("document signature carries no issuer fingerprint")
      }
      // Subpacket body = version octet || fingerprint; the version must
      // match the v6 signature that carries it (§5.2.3.35).
      guard b.length() == 33 else {
        abort("issuer fingerprint is not a v6 32-octet value")
      }
      guard b[0].to_int() == 6 else {
        abort("issuer fingerprint version octet is not 6")
      }
      issuer = b.exact_view()[1:].to_owned()
      break
    }
  }
  assert_eq(issuer, sign.secret.public.fingerprint())
  assert_true(@api.verify_detached(data, sig, key.to_public()) is Ok)
}

///|
/// The generated certificate round-trips through armor with both subkeys
/// and the embedded binding intact, and the encryption subkey carries a
/// message round-trip.
test "v6 dual-subkey key round-trips export and encryption" {
  let key = @api.generate_ed25519_v6_key_with_signing_subkey(
    "Dual V6 <dualv6@example.com>",
  )
  let back = @api.PrivateKey::from_armored(key.to_armored())
  guard back.subkeys.length() == 2 else { abort("round-trip lost subkeys") }
  let sign = back.subkeys[1]
  // The embedded binding survives the re-export with its shape intact.
  let round_embedded = @packet.find_subpacket(
    sign.binding.unhashed_subpackets,
    @packet.SIGSUB_EMBEDDED_SIGNATURE,
  )
  guard round_embedded is Some(rb) else {
    abort("round-trip lost the embedded binding")
  }
  let re = @packet.SignaturePacket::parse(rb.exact_view())
  guard re.sig_type() == @packet.PrimaryKeyBinding else {
    abort("round-tripped embedded signature has the wrong type")
  }
  guard re.version() == 6 else {
    abort("round-tripped embedded signature is not v6")
  }
  let data = @primitives.utf8_bytes("v6 dual-subkey round trip")
  let msg = @api.encrypt_to_recipients(data, [back.to_public()])
  assert_eq(
    @utf8.decode_lossy(@api.decrypt_with_private_key(msg, back).exact_view()),
    "v6 dual-subkey round trip",
  )
}
