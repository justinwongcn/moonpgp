///|
/// Serialize to binary packets: SecretKey || [DirectKeySig] ||
/// [UserID || cert] || [SecretSubkey || binding ]. A v6 key without a
/// User ID writes only the Direct Key signature.
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  match self.direct_signature {
    Some(b) =>
      w.bytes(
        @packet.serialize_packet(@packet.Signature, b.to_body().exact_view()).exact_view(),
      )
    None => ()
  }
  // Emit every certified User ID with its own certification (M5). A
  // bare v6 key emits none here; its Direct Key signature was already
  // written above.
  for binding in self.user_ids {
    let uid = @primitives.utf8_bytes(binding.user_id)
    w.bytes(
      @packet.serialize_packet(@packet.UserId, uid.exact_view()).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(
        @packet.Signature,
        binding.self_signature.to_body().exact_view(),
      ).exact_view(),
    )
  }
  match self.encryption_subkey {
    Some(subkey) => {
      w.bytes(
        @packet.serialize_packet(
          @packet.SecretSubkey,
          subkey.to_body().exact_view(),
        ).exact_view(),
      )
      match self.subkey_binding {
        Some(b) =>
          w.bytes(
            @packet.serialize_packet(
              @packet.Signature,
              b.to_body().exact_view(),
            ).exact_view(),
          )
        None => ()
      }
    }
    None => ()
  }
  w.to_bytes()
}

///|
/// Export as ASCII-armored private key block.
pub fn PrivateKey::to_armored(self : PrivateKey) -> String {
  @armor.PrivateKey.encode(self.to_bytes().exact_view())
}

///|
/// The Preferred AEAD Ciphersuites advertised by a key as (cipher, AEAD)
/// id pairs, most preferred first (RFC 9580 §5.2.3.15). Reads the
/// self-signature first, then the Direct Key signature of a v6 key, and
/// returns an empty list when the key advertises none.
pub fn PublicKey::preferred_aead(self : PublicKey) -> Array[(Int32, Int32)] {
  match self.self_signature().preferred_aead() {
    Some(list) => if !list.is_empty() { return list }
    None => ()
  }
  match self.direct_signature {
    Some(sig) =>
      match sig.preferred_aead() {
        Some(list) => return list
        None => ()
      }
    None => ()
  }
  []
}

///|
/// True when the key advertises v2 SEIPD support in its Features
/// subpacket (RFC 9580 §5.2.3.32).
pub fn PublicKey::supports_seipd_v2(self : PublicKey) -> Bool {
  if self.self_signature().supports_seipd_v2() {
    return true
  }
  match self.direct_signature {
    Some(sig) => sig.supports_seipd_v2()
    None => false
  }
}

///|
/// Public half to binary packets.
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.PublicKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  match self.direct_signature {
    Some(b) =>
      w.bytes(
        @packet.serialize_packet(@packet.Signature, b.to_body().exact_view()).exact_view(),
      )
    None => ()
  }
  // Emit every certified User ID with its own certification (M5). A
  // bare v6 key emits none here; its Direct Key signature was already
  // written above.
  for binding in self.user_ids {
    let uid = @primitives.utf8_bytes(binding.user_id)
    w.bytes(
      @packet.serialize_packet(@packet.UserId, uid.exact_view()).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(
        @packet.Signature,
        binding.self_signature.to_body().exact_view(),
      ).exact_view(),
    )
  }
  match self.encryption_subkey {
    Some(subkey) => {
      w.bytes(
        @packet.serialize_packet(
          @packet.PublicSubkey,
          subkey.to_body().exact_view(),
        ).exact_view(),
      )
      match self.subkey_binding {
        Some(b) =>
          w.bytes(
            @packet.serialize_packet(
              @packet.Signature,
              b.to_body().exact_view(),
            ).exact_view(),
          )
        None => ()
      }
    }
    None => ()
  }
  w.to_bytes()
}

///|
/// Export as ASCII-armored public key block.
pub fn PublicKey::to_armored(self : PublicKey) -> String {
  @armor.PublicKey.encode(self.to_bytes().exact_view())
}

///|
fn packets_of(data : BytesView) -> Array[@packet.RawPacket] raise {
  @packet.parse_packets(data)
}

///|
fn build_public(packets : Array[@packet.RawPacket]) -> PublicKey raise {
  let mut primary : @packet.PublicKeyPacket? = None
  // User IDs pair with the certification that follows them (wire order;
  // a later certification of the same User ID replaces the earlier one).
  let bindings : Array[UserIdBinding] = []
  let mut pending_uid : String? = None
  let mut direct : @packet.SignaturePacket? = None
  let mut subkey : @packet.PublicKeyPacket? = None
  let mut binding : @packet.SignaturePacket? = None
  let revocations : Array[@packet.SignaturePacket] = []
  let mut subkey_revocation : @packet.SignaturePacket? = None
  for p in packets {
    match p.tag() {
      @packet.PublicKey =>
        primary = Some(@packet.PublicKeyPacket::parse(p.body().exact_view()))
      @packet.SecretKey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        primary = Some(sk.public)
      }
      @packet.UserId =>
        // Lossy on purpose: a key with an undecodable User ID stays usable
        // for its subkeys (gopenpgp keeps raw bytes; we keep a best-effort
        // string instead of failing the whole key).
        pending_uid = Some(@utf8.decode_lossy(p.body().exact_view()))
      @packet.Signature => {
        let s = @packet.SignaturePacket::parse(p.body().exact_view())
        match s.sig_type() {
          @packet.PositiveCertification | @packet.GenericCertification => {
            let uid = match pending_uid {
              Some(u) => u
              // A certification before any User ID cannot be bound to
              // anything; keys are not required to interleave, so treat
              // it as an unbound stray and reject the import (strict).
              None =>
                @error.fail("api: certification without a preceding user id")
            }
            let cert = UserIdBinding::{ user_id: uid, self_signature: s, }
            // Last certification of the same User ID wins.
            let mut replaced = false
            for i in 0..<bindings.length() {
              if bindings[i].user_id == uid {
                bindings[i] = cert
                replaced = true
              }
            }
            if !replaced {
              bindings.push(cert)
            }
          }
          @packet.DirectSignature => direct = Some(s)
          @packet.SubkeyBinding => binding = Some(s)
          @packet.KeyRevocation => revocations.push(s)
          @packet.SubkeyRevocation => subkey_revocation = Some(s)
          // CertificationRevocation withdrawals are not modeled.
          _ => ()
        }
      }
      @packet.PublicSubkey =>
        subkey = Some(@packet.PublicKeyPacket::parse(p.body().exact_view()))
      @packet.SecretSubkey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        subkey = Some(sk.public)
      }
      _ => ()
    }
  }
  match primary {
    Some(p) => {
      // RFC 9580 §5.2.3.10: a v6 key must carry a valid Direct Key
      // signature before it may be used. A v6 key without a User ID uses
      // that signature as its key-level self-signature.
      if p.version() >= 6 && direct is None {
        @error.fail("api: v6 key has no direct-key signature")
      }
      // Only a bare key (no User ID) may rely on its Direct signature
      // alone; every certified User ID must carry a certification.
      if bindings.is_empty() && direct is None {
        @error.fail("api: key has no self-signature")
      }
      validate_key_signatures(p, bindings, direct, subkey, binding)
      PublicKey::{
        primary: p,
        user_ids: bindings,
        direct_signature: direct,
        encryption_subkey: subkey,
        subkey_binding: binding,
        revocations,
        subkey_revocation,
      }
    }
    None => @error.fail("api: no key packet found")
  }
}

///|
/// Import-time cryptographic validation (M1): every signature the key
/// model relies on must verify over the material it certifies. Revocation
/// signatures are excluded — their validity is time-dependent and they
/// are verified lazily by `is_revoked`.
fn validate_key_signatures(
  primary : @packet.PublicKeyPacket,
  bindings : Array[UserIdBinding],
  direct : @packet.SignaturePacket?,
  subkey : @packet.PublicKeyPacket?,
  binding : @packet.SignaturePacket?,
) -> Unit raise {
  for b in bindings {
    let ok = verify_key_signature(
      b.self_signature,
      primary,
      primary,
      user_id=b.user_id,
    ) catch {
      _ => false
    }
    if !ok {
      @error.fail("api: user id self-signature does not verify over the key")
    }
  }
  match direct {
    Some(d) => {
      let ok = verify_key_signature(d, primary, primary, direct=true) catch {
        _ => false
      }
      if !ok {
        @error.fail("api: direct-key signature does not verify over the key")
      }
    }
    None => ()
  }
  match (subkey, binding) {
    (Some(sk), Some(b)) => {
      let ok = verify_key_signature(b, primary, sk) catch { _ => false }
      if !ok {
        @error.fail(
          "api: subkey binding signature does not verify over the key",
        )
      }
    }
    _ => ()
  }
}

///|
/// Parse a transferable public key from binary packets.
pub fn PublicKey::from_bytes(data : BytesView) -> PublicKey raise {
  build_public(packets_of(data))
}

///|
/// Parse a transferable private key from binary packets. The secret
/// material stays in whatever state the wire had it (locked or unlocked);
/// use `PrivateKey::unlock` for locked keys.
pub fn PrivateKey::from_bytes(data : BytesView) -> PrivateKey raise {
  let packets = packets_of(data)
  let pub_half = build_public(packets)
  let mut primary : @packet.SecretKeyPacket? = None
  let mut subkey : @packet.SecretKeyPacket? = None
  let mut binding : @packet.SignaturePacket? = None
  for p in packets {
    match p.tag() {
      @packet.SecretKey =>
        primary = Some(@packet.SecretKeyPacket::parse(p.body().exact_view()))
      @packet.SecretSubkey =>
        subkey = Some(@packet.SecretKeyPacket::parse(p.body().exact_view()))
      @packet.Signature => {
        let s = @packet.SignaturePacket::parse(p.body().exact_view())
        if s.sig_type() == @packet.SubkeyBinding {
          binding = Some(s)
        }
      }
      _ => ()
    }
  }
  match primary {
    Some(p) =>
      PrivateKey::{
        primary: p,
        user_ids: pub_half.user_ids,
        direct_signature: pub_half.direct_signature,
        encryption_subkey: subkey,
        subkey_binding: binding,
        revocations: pub_half.revocations,
        subkey_revocation: pub_half.subkey_revocation,
      }
    None => @error.fail("api: no secret key packet found")
  }
}

///|
/// Parse an armored key block (public or private) into a PrivateKey when
/// it carries secret material.
pub fn PrivateKey::from_armored(text : String) -> PrivateKey raise {
  let block = @armor.decode(text)
  match block.armor_type() {
    @armor.PrivateKey => PrivateKey::from_bytes(block.data().exact_view())
    _ => @error.fail("api: not a private key armor block")
  }
}

///|
/// Parse an armored key block into a public key; a private-key block is
/// accepted and stripped to its public half.
pub fn PublicKey::from_armored(text : String) -> PublicKey raise {
  let block = @armor.decode(text)
  match block.armor_type() {
    @armor.PublicKey => PublicKey::from_bytes(block.data().exact_view())
    @armor.PrivateKey =>
      PrivateKey::from_bytes(block.data().exact_view()).to_public()
    _ => @error.fail("api: not a key armor block")
  }
}
