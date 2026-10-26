///|
/// Serialize to binary packets: SecretKey || [revocation] ||
/// [DirectKeySig] || [UserID || cert] || [SecretSubkey || binding ]. A v6
/// key without a User ID writes only the Direct Key signature.
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(
      @packet.SecretKey,
      self.primary.to_body().exact_view(),
    ).exact_view(),
  )
  // Primary-key revocations sit straight after the primary key, before
  // any Direct Key signature or User ID (RFC 9580 §10.1.1/§10.1.3;
  // consolidation fix: these were silently dropped on re-export, so a
  // round-tripped certificate lost its revocation status).
  for r in self.revocations {
    w.bytes(
      @packet.serialize_packet(@packet.Signature, r.to_body().exact_view()).exact_view(),
    )
  }
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
  for c in self.subkeys {
    w.bytes(
      @packet.serialize_packet(
        @packet.SecretSubkey,
        c.secret.to_body().exact_view(),
      ).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(
        @packet.Signature,
        c.binding.to_body().exact_view(),
      ).exact_view(),
    )
    match c.revocation {
      Some(r) =>
        w.bytes(
          @packet.serialize_packet(@packet.Signature, r.to_body().exact_view()).exact_view(),
        )
      None => ()
    }
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
  // Primary-key revocations sit straight after the primary key (see
  // PrivateKey::to_bytes).
  for r in self.revocations {
    w.bytes(
      @packet.serialize_packet(@packet.Signature, r.to_body().exact_view()).exact_view(),
    )
  }
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
  for c in self.subkeys {
    w.bytes(
      @packet.serialize_packet(
        @packet.PublicSubkey,
        c.key.to_body().exact_view(),
      ).exact_view(),
    )
    w.bytes(
      @packet.serialize_packet(
        @packet.Signature,
        c.binding.to_body().exact_view(),
      ).exact_view(),
    )
    match c.revocation {
      Some(r) =>
        w.bytes(
          @packet.serialize_packet(@packet.Signature, r.to_body().exact_view()).exact_view(),
        )
      None => ()
    }
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
/// One subkey as it appeared on the wire during a transferable-key walk:
/// the public half, the secret packet when the wire carried one, and the
/// binding/revocation signatures that followed it.
priv struct ParsedSubkey {
  public : @packet.PublicKeyPacket
  secret : @packet.SecretKeyPacket?
  mut binding : @packet.SignaturePacket?
  mut revocation : @packet.SignaturePacket?
}

///|
/// The result of walking a transferable key's packets once, shared by the
/// public and private import paths so the two cannot disagree about what
/// the wire said.
priv struct ParsedKey {
  primary_pub : @packet.PublicKeyPacket
  primary_secret : @packet.SecretKeyPacket?
  user_ids : Array[UserIdBinding]
  direct : @packet.SignaturePacket?
  subkeys : Array[ParsedSubkey]
  revocations : Array[@packet.SignaturePacket]
}

///|
/// Walk the packet stream of a transferable key once: primary packet,
/// User IDs with their certifications, the Direct Key signature, every
/// subkey with its own binding (and revocation), and primary-key
/// revocations. Bindings and revocations attach to the most recent
/// subkey, so a normal `Subkey || Binding [|| Revocation]` sequence pairs
/// correctly no matter how many subkeys the certificate carries (N2).
fn parse_transferable(packets : Array[@packet.RawPacket]) -> ParsedKey raise {
  let mut primary_pub : @packet.PublicKeyPacket? = None
  let mut primary_secret : @packet.SecretKeyPacket? = None
  // User IDs pair with the certification that follows them (wire order;
  // a later certification of the same User ID replaces the earlier one).
  let bindings : Array[UserIdBinding] = []
  let mut pending_uid : String? = None
  let mut direct : @packet.SignaturePacket? = None
  let subkeys : Array[ParsedSubkey] = []
  let revocations : Array[@packet.SignaturePacket] = []
  for p in packets {
    match p.tag() {
      @packet.PublicKey =>
        primary_pub = Some(
          @packet.PublicKeyPacket::parse(p.body().exact_view()),
        )
      @packet.SecretKey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        primary_pub = Some(sk.public)
        primary_secret = Some(sk)
      }
      @packet.UserId =>
        // Lossy on purpose: a key with an undecodable User ID stays usable
        // for its subkeys (gopenpgp keeps raw bytes; we keep a best-effort
        // string instead of failing the whole key).
        pending_uid = Some(@utf8.decode_lossy(p.body().exact_view()))
      @packet.Signature => {
        let s = @packet.SignaturePacket::parse(p.body().exact_view())
        match s.sig_type() {
          // All four self-certification types 0x10-0x13 bind the User ID
          // (N3): gpg keys certified as casual/persona self-sigs are just
          // as much transferable keys as positive ones.
          @packet.PositiveCertification
          | @packet.GenericCertification
          | @packet.PersonaCertification
          | @packet.CasualCertification => {
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
          @packet.SubkeyBinding =>
            // A binding after the last subkey re-binds it (last wins); a
            // binding with no subkey before it certifies nothing.
            if subkeys.length() > 0 {
              let last = subkeys[subkeys.length() - 1]
              last.binding = Some(s)
            }
          @packet.KeyRevocation => revocations.push(s)
          @packet.SubkeyRevocation =>
            if subkeys.length() > 0 {
              let last = subkeys[subkeys.length() - 1]
              last.revocation = Some(s)
            }
          // CertificationRevocation withdrawals are not modeled.
          _ => ()
        }
      }
      @packet.PublicSubkey =>
        subkeys.push(ParsedSubkey::{
          public: @packet.PublicKeyPacket::parse(p.body().exact_view()),
          secret: None,
          binding: None,
          revocation: None,
        })
      @packet.SecretSubkey => {
        let sk = @packet.SecretKeyPacket::parse(p.body().exact_view())
        subkeys.push(ParsedSubkey::{
          public: sk.public,
          secret: Some(sk),
          binding: None,
          revocation: None,
        })
      }
      _ => ()
    }
  }
  match primary_pub {
    Some(p) =>
      ParsedKey::{
        primary_pub: p,
        primary_secret,
        user_ids: bindings,
        direct,
        subkeys,
        revocations,
      }
    None => @error.fail("api: no key packet found")
  }
}

///|
/// Structural requirements plus cryptographic validation of everything
/// the key model relies on — shared by the public and private import
/// paths so neither can accept what the other rejects.
fn check_transferable(parsed : ParsedKey) -> Unit raise {
  // RFC 9580 §5.2.3.10: a v6 key must carry a valid Direct Key
  // signature before it may be used. A v6 key without a User ID uses
  // that signature as its key-level self-signature.
  if parsed.primary_pub.version() >= 6 && parsed.direct is None {
    @error.fail("api: v6 key has no direct-key signature")
  }
  // Only a bare key (no User ID) may rely on its Direct signature
  // alone; every certified User ID must carry a certification.
  if parsed.user_ids.is_empty() && parsed.direct is None {
    @error.fail("api: key has no self-signature")
  }
  validate_key_signatures(
    parsed.primary_pub,
    parsed.user_ids,
    parsed.direct,
    parsed.subkeys,
  )
}

///|
/// Import-time structural and cryptographic validation, then assembly
/// into a `PublicKey`.
fn build_public(packets : Array[@packet.RawPacket]) -> PublicKey raise {
  let parsed = parse_transferable(packets)
  check_transferable(parsed)
  let subkeys : Array[SubkeyCert] = []
  for s in parsed.subkeys {
    // N1: validation above guarantees the binding exists and verifies.
    subkeys.push(SubkeyCert::{
      key: s.public,
      binding: s.binding.unwrap(),
      revocation: s.revocation,
    })
  }
  PublicKey::{
    primary: parsed.primary_pub,
    user_ids: parsed.user_ids,
    direct_signature: parsed.direct,
    subkeys,
    revocations: parsed.revocations,
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
  subkeys : Array[ParsedSubkey],
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
  for s in subkeys {
    // N1 (RFC 9580 §10.1): a transferable subkey MUST carry a binding
    // signature. Accepting an unbound subkey let a subkey injected into a
    // forwarded certificate be treated as encryption-capable without any
    // authentication by the primary key.
    let b = match s.binding {
      Some(b) => b
      None =>
        @error.fail("api: subkey has no binding signature (RFC 9580 §10.1)")
    }
    let ok = verify_key_signature(b, primary, s.public) catch { _ => false }
    if !ok {
      @error.fail("api: subkey binding signature does not verify over the key")
    }
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
  let parsed = parse_transferable(packets_of(data))
  check_transferable(parsed)
  let primary = match parsed.primary_secret {
    Some(p) => p
    None => @error.fail("api: no secret key packet found")
  }
  // A private certificate may carry public-only subkeys (an export that
  // skipped some secret material); they are validated like any other
  // subkey but contribute no usable secret here.
  let subkeys : Array[SecretSubkeyCert] = []
  for s in parsed.subkeys {
    let secret = match s.secret {
      Some(sk) => sk
      None => continue
    }
    subkeys.push(SecretSubkeyCert::{
      secret,
      binding: s.binding.unwrap(),
      revocation: s.revocation,
    })
  }
  PrivateKey::{
    primary,
    user_ids: parsed.user_ids,
    direct_signature: parsed.direct,
    subkeys,
    revocations: parsed.revocations,
  }
}

///|
/// Parse an armored key block (public or private) into a PrivateKey when
/// it carries secret material.
///
/// # Example
///
/// ```mbt check
/// test "armor round trip preserves the fingerprint" {
///   let key = @api.generate_ed25519_key("A <a@example.com>")
///   let re = @api.PrivateKey::from_armored(key.to_armored())
///   assert_eq(re.fingerprint(), key.fingerprint())
/// }
/// ```
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
