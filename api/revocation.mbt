///|
/// Revocation certificate generation (task 2a): OpenPGP's damage-control
/// primitive — until this existed, a moonpgp user could consume key
/// revocations (`is_revoked`, verified lazily) but never create one for
/// their own key.
///
/// The hash shapes match the consumer side exactly: a primary-key
/// revocation (type 0x20) hashes like a Direct Key signature, a subkey
/// revocation (0x28) like a SubkeyBinding — both already what
/// `verify_key_signature` checks in `is_revoked` / `subkey_revoked_at`.

///|
/// Revocation reason codes (RFC 9580 §5.2.3.31). Reason 32 (User ID no
/// longer valid) belongs to certification revocations, which this library
/// does not model.
pub(all) enum RevocationReason {
  /// No reason specified.
  NoReason
  /// Replaced by a newer key.
  Superseded
  /// Secret material compromised.
  Compromised
  /// Retired; no longer used.
  Retired
} derive(Eq, Debug)

///|
pub fn RevocationReason::number(self : RevocationReason) -> Int32 {
  match self {
    NoReason => 0
    Superseded => 1
    Compromised => 2
    Retired => 3
  }
}

///|
/// The Revocation Reason subpacket body: one reason octet followed by the
/// UTF-8 message (possibly empty).
fn revocation_reason_subpacket(
  reason : RevocationReason,
  message : String?,
) -> @packet.SigSubpacket {
  let body = Bytes::from_array([reason.number().to_byte()]).add(
    @primitives.utf8_bytes(message.unwrap_or("")),
  )
  { critical: false, sub_type: @packet.SIGSUB_REVOCATION_REASON, body, }
}

///|
/// The hashed subpacket area shared by both revocation signature kinds.
fn revocation_hashed_area(
  pub_packet : @packet.PublicKeyPacket,
  now : Int32,
  reason : RevocationReason,
  message : String?,
) -> Array[@packet.SigSubpacket] raise {
  let hashed : Array[@packet.SigSubpacket] = [
    { ..creation_subpacket(now), critical: true, },
    revocation_reason_subpacket(reason, message),
  ]
  if pub_packet.version() >= 6 {
    hashed.push(issuer_fingerprint_subpacket(pub_packet))
  }
  hashed
}

///|
/// Create a primary-key revocation signature (type 0x20) signed by the
/// primary itself; hashes exactly like the Direct Key signature the
/// consumer side verifies.
fn make_key_revocation_signature(
  secret_packet : @packet.SecretKeyPacket,
  pub_packet : @packet.PublicKeyPacket,
  reason : RevocationReason,
  message : String?,
  now : Int32,
) -> @packet.SignaturePacket raise {
  let v6 = pub_packet.version() >= 6
  // v6 identifies the issuer by the fingerprint subpacket in the hashed
  // area; v4 needs the Issuer Key ID subpacket or verifiers cannot
  // attribute the signature at all (caught by cross-checking with gpg,
  // which silently ignored the issuerless revocation).
  let unhashed : Array[@packet.SigSubpacket] = if v6 {
    []
  } else {
    [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: pub_packet.key_id(),
      },
    ]
  }
  let sig : @packet.SignaturePacket = {
    version: if v6 {
      6
    } else {
      4
    },
    sig_type: @packet.KeyRevocation,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: revocation_hashed_area(pub_packet, now, reason, message),
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: if v6 {
      @primitives.random_bytes(
        @packet.salt_size_of_hash(@primitives.Sha256.number()),
      )
    } else {
      Bytes::new(0)
    },
    sig_params: [],
  }
  let digest = hash_direct_key(sig, pub_packet)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Create a subkey revocation signature (type 0x28) signed by the primary;
/// hashes exactly like the subkey binding the consumer side verifies.
fn make_subkey_revocation_signature(
  secret_packet : @packet.SecretKeyPacket,
  primary_pub : @packet.PublicKeyPacket,
  subkey_pub : @packet.PublicKeyPacket,
  reason : RevocationReason,
  message : String?,
  now : Int32,
) -> @packet.SignaturePacket raise {
  let v6 = primary_pub.version() >= 6
  // The issuer of a subkey revocation is the PRIMARY key (see the v4
  // issuer note in make_key_revocation_signature).
  let unhashed : Array[@packet.SigSubpacket] = if v6 {
    []
  } else {
    [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: primary_pub.key_id(),
      },
    ]
  }
  let sig : @packet.SignaturePacket = {
    version: if v6 {
      6
    } else {
      4
    },
    sig_type: @packet.SubkeyRevocation,
    pub_algo: secret_packet.public.algo(),
    hash_algo: @primitives.Sha256.number(),
    hashed_subpackets: revocation_hashed_area(primary_pub, now, reason, message),
    unhashed_subpackets: unhashed,
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: if v6 {
      @primitives.random_bytes(
        @packet.salt_size_of_hash(@primitives.Sha256.number()),
      )
    } else {
      Bytes::new(0)
    },
    sig_params: [],
  }
  let digest = hash_binding(sig, primary_pub, subkey_pub)
  finish_signature(sig, secret_packet, @primitives.Sha256, digest.exact_view())
}

///|
/// Generate, but do not apply, a standalone revocation certificate for the
/// primary key: a single key-revocation signature packet in PUBLIC KEY
/// BLOCK armor — the `.rev` shape `gpg --gen-revoke` emits (gpg refuses to
/// --import a bare Signature armor block, verified against 2.4.5). The
/// owner distributes it out of band; anyone can apply it to their copy of
/// the public key.
pub fn generate_revocation_certificate(
  key : PrivateKey,
  reason~ : RevocationReason = NoReason,
  message? : String,
  created? : Int32,
) -> String raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let sig = make_key_revocation_signature(
    key.primary,
    key.primary.public,
    reason,
    message,
    now,
  )
  @armor.PublicKey.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
}

///|
/// Return a copy of `key` with a fresh primary-key revocation appended;
/// the certificate round-trips with the revocation intact and every
/// lifecycle gate (`is_revoked`, `can_encrypt`, `can_verify`, signature
/// verification) sees the key as revoked.
pub fn revoke_key(
  key : PrivateKey,
  reason~ : RevocationReason = NoReason,
  message? : String,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let sig = make_key_revocation_signature(
    key.primary,
    key.primary.public,
    reason,
    message,
    now,
  )
  let revocations = key.revocations.copy()
  revocations.push(sig)
  { ..key, revocations, }
}

///|
/// Return a copy of `key` with a revocation signature on the subkey whose
/// key id matches `subkey_id`. A revoked subkey drops out of encryption
/// selection immediately; decryption with it stays possible (mail that
/// arrived before the revocation must keep decrypting, mirroring
/// `KeyRing::find_decryption_key`).
pub fn revoke_subkey(
  key : PrivateKey,
  subkey_id : BytesView,
  reason~ : RevocationReason = NoReason,
  message? : String,
  created? : Int32,
) -> PrivateKey raise {
  let now = match created {
    Some(t) => t
    None => @primitives.unix_now().to_int()
  }
  let subkeys : Array[SecretSubkeyCert] = []
  let mut found = false
  for c in key.subkeys {
    let id = c.secret.public.key_id() catch { _ => Bytes::new(0) }
    if !found && id.length() > 0 && id.equal(subkey_id.to_owned()) {
      let sig = make_subkey_revocation_signature(
        key.primary,
        key.primary.public,
        c.secret.public,
        reason,
        message,
        now,
      )
      subkeys.push({ ..c, revocation: Some(sig), })
      found = true
    } else {
      subkeys.push(c)
    }
  }
  guard found else {
    @error.fail("api: no subkey of this key matches the given key id")
  }
  { ..key, subkeys, }
}

///|
/// Parse an armored standalone revocation certificate, check it is a
/// primary-key revocation that cryptographically verifies over this key,
/// and return a copy with it appended. Anything else (wrong armor type, a
/// non-revocation signature, a signature for another key) is an error —
/// an invalid revocation must not be able to disable a key.
pub fn PrivateKey::apply_revocation_certificate(
  self : PrivateKey,
  armored : String,
) -> PrivateKey raise {
  let sig = parse_revocation_certificate(armored)
  let ok = verify_key_signature(
    sig,
    self.primary.public,
    self.primary.public,
    direct=true,
  ) catch {
    _ => false
  }
  guard ok else {
    @error.fail("api: the revocation certificate does not verify over this key")
  }
  let revocations = self.revocations.copy()
  revocations.push(sig)
  { ..self, revocations, }
}

///|
/// The public-half twin of `PrivateKey::apply_revocation_certificate`.
pub fn PublicKey::apply_revocation_certificate(
  self : PublicKey,
  armored : String,
) -> PublicKey raise {
  let sig = parse_revocation_certificate(armored)
  let ok = verify_key_signature(sig, self.primary, self.primary, direct=true) catch {
    _ => false
  }
  guard ok else {
    @error.fail("api: the revocation certificate does not verify over this key")
  }
  let revocations = self.revocations.copy()
  revocations.push(sig)
  { ..self, revocations, }
}

///|
/// Decode a standalone revocation certificate. The label is not load
/// bearing — gpg writes `.rev` files as PUBLIC KEY BLOCK armor holding
/// just the signature packet, while a Signature-labeled block is equally
/// valid — so both are accepted and the packet inside decides.
fn parse_revocation_certificate(
  armored : String,
) -> @packet.SignaturePacket raise {
  let block = @armor.decode(armored)
  guard block.armor_type() == @armor.Signature ||
    block.armor_type() == @armor.PublicKey else {
    @error.fail("api: not a revocation certificate armor block")
  }
  let packets = @packet.parse_packets(block.data().exact_view())
  let mut sig : @packet.SignaturePacket? = None
  for p in packets {
    if p.tag() == @packet.Signature {
      sig = Some(@packet.SignaturePacket::parse(p.body().exact_view()))
      break
    }
  }
  let s = match sig {
    Some(s) => s
    None => @error.fail("api: no signature packet in armor block")
  }
  guard s.sig_type() == @packet.KeyRevocation else {
    @error.fail(
      "api: the certificate is not a key revocation (type \{s.sig_type().number()})",
    )
  }
  s
}

///|
pub extend RevocationReason with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RevocationReason with Eq::{not_equal, equal}
