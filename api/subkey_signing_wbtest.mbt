///|
/// Task 2b: document signatures choose their issuing component by the
/// certificate's capabilities — a cert-only primary delegates to its
/// signing subkey (the shape GnuPG's dual-subkey certificates use), a
/// sign-capable primary keeps signing itself.

///|
/// Rewrite the key-flags octet of a key's self-signature IN MEMORY (the
/// signing selector only reads flags; nothing here is re-imported, so the
/// signature itself does not need to stay valid wire data).
fn with_self_sig_flags(key : PrivateKey, flags : Int32) -> PrivateKey {
  let old = key.self_signature()
  let hashed : Array[@packet.SigSubpacket] = []
  for sp in old.hashed_subpackets {
    if sp.sub_type == @packet.SIGSUB_KEY_FLAGS {
      hashed.push({ ..sp, body: Bytes::from_array([flags.to_byte()]), })
    } else {
      hashed.push(sp)
    }
  }
  let sig = { ..old, hashed_subpackets: hashed, }
  {
    ..key,
    user_ids: [
      UserIdBinding::{
        user_id: key.user_id(),
        self_signature: sig,
        revocation: None,
      },
    ],
  }
}

///|
/// A certificate with a cert-only primary and a bound signing subkey.
fn dual_component_key() -> PrivateKey raise {
  let base = generate_ed25519_key("Dual <dual@example.com>")
  let created = base.primary.public.creation_time
  // A genuinely signed certify-only primary (flags 0x01): wire-valid, so
  // the certificate round-trips through import and gpg accepts it.
  let cert_only = make_self_signature(
    base.primary,
    base.primary.public,
    base.user_id(),
    created,
    key_flags=0x01,
  )
  let signing = build_eddsa_secret_key_packet(
    @primitives.random_bytes(32),
    created,
  )
  let binding = make_binding_signature(
    base.primary,
    base.primary.public,
    signing.public,
    created,
    key_flags=0x02,
    subkey_secret=signing,
  )
  {
    ..base,
    user_ids: [
      UserIdBinding::{
        user_id: base.user_id(),
        self_signature: cert_only,
        revocation: None,
      },
    ],
    subkeys: [
      SecretSubkeyCert::{
        secret: base.subkeys[0].secret,
        binding: base.subkeys[0].binding,
        revocation: None,
      },
      SecretSubkeyCert::{ secret: signing, binding, revocation: None, },
    ],
  }
}

///|
/// The issuer key id a Signature armor block carries.
fn issuer_of(armored : String) -> Bytes raise {
  let block = @armor.decode(armored)
  let packets = @packet.parse_packets(
    @armor.ArmorBlock::data(block).exact_view(),
  )
  let mut issuer : Bytes? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      issuer = @packet.SignaturePacket::parse(p.body().exact_view()).issuer_key_id()
    }
  }
  issuer.unwrap()
}

///|
test "a cert-only primary signs through its signing subkey" {
  let key = dual_component_key()
  let data = @primitives.utf8_bytes("signed by the subkey component")
  let sig = sign_detached(data.exact_view(), key)
  // The signature is subkey-issued and verifies against the certificate.
  assert_true(issuer_of(sig).equal(key.subkeys[1].secret.public.key_id()))
  assert_eq(verify_detached(data.exact_view(), sig, key.to_public()), Ok)
}

///|
test "a sign-capable primary keeps signing itself" {
  let key = generate_ed25519_key("Solo <solo@example.com>")
  let data = @primitives.utf8_bytes("primary still signs")
  let sig = sign_detached(data.exact_view(), key)
  assert_true(issuer_of(sig).equal(key.primary.public.key_id()))
  assert_eq(verify_detached(data.exact_view(), sig, key.to_public()), Ok)
}

///|
test "cert-only primary without a signing subkey fails loudly" {
  // Cert-only primary whose only subkey is encryption-flagged.
  let key = with_self_sig_flags(
    generate_ed25519_key("None <none@example.com>"),
    0x01,
  )
  let raised = try {
    let _ = sign_detached(b"x".exact_view(), key)
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("no component"))
      true
    }
  }
  assert_true(raised)
}

///|
test "a revoked key refuses to sign" {
  let key = revoke_key(generate_ed25519_key("Rv <rv@example.com>"))
  let raised = try {
    let _ = sign_detached(b"x".exact_view(), key)
    false
  } catch {
    e => {
      assert_true(e.to_string().contains("refusing to sign"))
      true
    }
  }
  assert_true(raised)
}

///|
test "subkey-issued sign_and_encrypt round-trips with verification" {
  let signer = dual_component_key()
  let recipient = generate_ed25519_key("Rcp <rcp@example.com>")
  let data = @primitives.utf8_bytes("signed by subkey, sealed to recipient")
  let armored = sign_and_encrypt(data, signer, [recipient.to_public()])
  let (extracted, status) = decrypt_and_verify(
    armored,
    [recipient],
    Some(signer.to_public()),
  )
  assert_eq(extracted, data)
  assert_eq(status, Ok)
}
