///|
/// v6 X25519 public-key encryption for session keys (RFC 9580 §5.1.6 and
/// §5.5.5.7). Unlike Curve25519Legacy this uses the native 32-octet keys,
/// the fixed HKDF info "OpenPGP X25519", and AES-128 key wrap with no
/// padding or checksum; the symmetric algorithm comes from the v2 SEIPD
/// packet rather than from the wrapped payload.

///|
/// The RFC 9580 §5.1.6 HKDF `info` string (no trailing NUL).
const X25519_KDF_INFO : String = "OpenPGP X25519"

///|
/// The native 32-octet public key of a v6 X25519 key packet.
fn x25519_native_public(pub_packet : @packet.PublicKeyPacket) -> Bytes raise {
  guard pub_packet.algo() == @packet.X25519 else {
    @error.fail("api: not an X25519 key")
  }
  let params = pub_packet.params()
  guard params.length() == 1 && params[0].length() == 32 else {
    @error.fail("api: bad X25519 public key material")
  }
  params[0]
}

///|
/// The native 32-octet secret key of an unlocked X25519 packet. A v4
/// secret key packet appends the 2-octet checksum after the 32 native
/// octets (v6 does not); strip it so both versions yield the raw scalar.
fn x25519_native_secret(sk : @packet.SecretKeyPacket) -> Bytes raise {
  guard sk.s2k_usage == 0 else {
    @error.fail("api: secret key material is locked; unlock it first")
  }
  guard sk.public.algo() == @packet.X25519 else {
    @error.fail("api: not an X25519 key")
  }
  let want = if sk.public.version() >= 6 { 32 } else { 34 }
  guard sk.secret_material.length() == want else {
    @error.fail("api: bad X25519 secret key material")
  }
  if want == 32 {
    sk.secret_material
  } else {
    sk.secret_material[0:32].to_owned()
  }
}

///|
/// The X25519 key-encryption key (RFC 9580 §5.1.6): HKDF-SHA256 with no
/// salt, `info = "OpenPGP X25519"`, and IKM =
/// `ephemeral public || recipient public || shared secret`; 16 octets feed
/// AES-128 key wrap.
fn x25519_kek(
  eph_public : BytesView,
  recipient_public : BytesView,
  shared : BytesView,
) -> Bytes raise {
  let ikm = @primitives.concat3(eph_public, recipient_public, shared)
  @primitives.hkdf_sha256(
    ikm,
    Bytes::new(0),
    @primitives.utf8_bytes(X25519_KDF_INFO),
    16,
  )
}

///|
/// X25519-wrap the session key to a v6 recipient: fresh ephemeral scalar,
/// shared secret, §5.1.6 KDF, RFC 3394 wrap. Returns the 32-octet native
/// ephemeral public key and the wrapped key.
fn x25519_wrap_session_key(
  recipient_pub : @packet.PublicKeyPacket,
  session_key : BytesView,
) -> (Bytes, Bytes) raise {
  let eph = @pki.x25519_generate()
  let peer = x25519_native_public(recipient_pub)
  let shared = @pki.x25519_shared_secret(
    eph.scalar.exact_view(),
    peer.exact_view(),
  )
  let kek = x25519_kek(
    eph.public.exact_view(),
    peer.exact_view(),
    shared.exact_view(),
  )
  let wrapped = @cipher.aes_key_wrap(kek.exact_view(), session_key)
  (eph.public, wrapped)
}

///|
/// X25519-unwrap a PKESK's session key. Returns (symmetric algorithm id,
/// session key). A v6 PKESK returns 0 because the v2 SEIPD names the cipher
/// itself; a **v3** PKESK carries the 1-octet cipher id in cleartext in
/// front of the wrapped key (RFC 9580 §5.1.6), so it is peeled off here and
/// returned.
fn x25519_unwrap_session_key(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> (Int32, Bytes) raise {
  let secret = x25519_native_secret(sk)
  let (algo, wrapped) = if pkesk.version() == 3 {
    let enc = pkesk.encrypted()
    guard enc.length() >= 1 else {
      @error.fail("api: a v3 X25519 PKESK carries no algorithm octet")
    }
    let algo = enc[0].to_int()
    guard @primitives.cipher_algo_of_number(algo) is Some(_) else {
      @error.fail("api: unexpected session key cipher \{algo}")
    }
    (algo, enc[1:enc.length()])
  } else {
    (0, pkesk.encrypted())
  }
  let eph = pkesk.ecdh_ephemeral()
  guard eph.length() == 32 else { @error.fail("api: bad X25519 ephemeral key") }
  let shared = @pki.x25519_shared_secret(secret.exact_view(), eph.exact_view())
  let recipient = x25519_native_public(sk.public)
  let kek = x25519_kek(
    eph.exact_view(),
    recipient.exact_view(),
    shared.exact_view(),
  )
  (algo, @cipher.aes_key_unwrap(kek.exact_view(), wrapped))
}
