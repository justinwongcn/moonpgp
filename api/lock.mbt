///|
/// AEAD associated data for a protected secret key packet
/// (RFC 9580 §5.5.3): the packet tag byte in OpenPGP encoding followed by
/// the Public Key packet fields, starting with the version.
fn secret_key_associated_data(
  key : @packet.SecretKeyPacket,
  tag : Int32,
) -> Bytes {
  @primitives.concat2(Bytes::from_array([tag.to_byte()]), key.public.to_body())
}

///|
/// HKDF `info` for a usage-253 secret key packet (RFC 9580 §5.5.3): packet
/// tag byte, packet version, cipher algorithm, and AEAD mode.
fn secret_key_hkdf_info(key : @packet.SecretKeyPacket, tag : Int32) -> Bytes {
  Bytes::from_array([
    tag.to_byte(),
    key.public.version().to_byte(),
    key.cipher_algo.to_byte(),
    key.aead_algo.to_byte(),
  ])
}

///|
/// The AEAD mode of a usage-253 secret key packet.
fn secret_key_aead_mode(
  key : @packet.SecretKeyPacket,
) -> @cipher.AeadMode raise {
  match @cipher.aead_mode_of_number(key.aead_algo) {
    Some(m) => m
    None => @error.fail("api: unknown AEAD algorithm \{key.aead_algo}")
  }
}

///|
/// Decrypt (unlock) the secret material of a v4/v6 key packet in place.
/// Supports S2K usage 253 (AEAD + HKDF key separation, including Argon2
/// S2K), 254 (SHA-1 check) and 255 / legacy cipher-id (2-octet checksum)
/// with AES ciphers. The result carries usage 0 plaintext material.
///
/// `tag` is the packet tag byte (0xC5 Secret Key, 0xC7 Secret Subkey),
/// which RFC 9580 feeds into both HKDF `info` and the AEAD associated data.
fn unlock_secret_key(
  key : @packet.SecretKeyPacket,
  passphrase : String,
  tag : Int32,
  argon2_max_memory_kib : Int32,
) -> @packet.SecretKeyPacket raise {
  guard key.s2k_usage != 0 else { key }
  guard !key.dummy else {
    @error.fail("api: secret material is a GnuPG dummy (moved to a smartcard)")
  }
  // The read side accepts the legacy protection ciphers too (RFC 4880
  // §9.2 MUST 3DES; CAST5 was GnuPG's pre-AES default) — generation
  // still only ever writes AES (see `lock_secret_key`).
  guard @primitives.cipher_algo_of_number(key.cipher_algo) is Some(_) else {
    @error.fail("api: unsupported protection cipher \{key.cipher_algo}")
  }
  let algo = @error.require(
    @primitives.cipher_algo_of_number(key.cipher_algo),
    "api: unsupported protection cipher",
  )
  let s2k = (@s2k.parse(key.s2k_spec.exact_view()) catch {
      _ => @error.fail("api: bad S2K in locked key")
    }).0
  let pass = @primitives.utf8_bytes(passphrase)
  if key.s2k_usage == 253 {
    // RFC 9580 §5.5.3: the S2K key is stretched with HKDF-SHA256 (empty
    // salt, info = tag|version|cipher|aead) before it protects the
    // plaintext with the packet's AEAD mode; the tag replaces any checksum.
    let mode = secret_key_aead_mode(key)
    let s2k_key = s2k.derive_key_capped(
      pass.exact_view(),
      algo.key_size(),
      argon2_max_memory_kib,
    )
    let dek = @primitives.hkdf_sha256(
      s2k_key,
      Bytes::new(0),
      secret_key_hkdf_info(key, tag),
      algo.key_size(),
    )
    let bc = @primitives.new_block_cipher(algo, dek.exact_view())
    let ad = secret_key_associated_data(key, tag)
    let material = try {
      match mode {
        @cipher.Ocb =>
          @cipher.ocb_decrypt(
            bc,
            key.iv.exact_view(),
            ad.exact_view(),
            key.secret_material.exact_view(),
          )
        @cipher.Gcm =>
          @cipher.gcm_decrypt(
            bc,
            key.iv.exact_view(),
            ad.exact_view(),
            key.secret_material.exact_view(),
          )
        @cipher.Eax =>
          @cipher.eax_decrypt(
            bc,
            key.iv.exact_view(),
            ad.exact_view(),
            key.secret_material.exact_view(),
          )
      }
    } catch {
      _ =>
        @error.fail(
          "api: secret key decryption failed (wrong passphrase or corrupted key)",
        )
    }
    return @packet.SecretKeyPacket::{
      public: key.public,
      s2k_usage: 0,
      cipher_algo: 0,
      aead_algo: 0,
      s2k_spec: Bytes::new(0),
      iv: Bytes::new(0),
      secret_material: material,
      dummy: false,
    }
  }
  guard !s2k.is_argon2() else {
    // Parse already rejects this, but a caller-built packet could still
    // reach here; RFC 9580 §3.7.2.1 says Argon2 is AEAD-only.
    @error.fail("api: Argon2 S2K requires AEAD (usage 253) for a secret key")
  }
  let kek = s2k.derive_key_capped(
    pass.exact_view(),
    algo.key_size(),
    argon2_max_memory_kib,
  )
  let bc = @primitives.new_block_cipher(algo, kek.exact_view())
  let plain = @cipher.cfb_decrypt(
    bc,
    key.iv.exact_view(),
    key.secret_material.exact_view(),
  ) catch {
    _ => @error.fail("api: secret key decryption failed")
  }
  // Split off the trailing check: 20-byte SHA-1 (usage 254) or 2-byte sum.
  let check_len : Int32 = if key.s2k_usage == 254 { 20 } else { 2 }
  guard plain.length() > check_len else {
    @error.fail("api: decrypted secret material too short")
  }
  let material = plain[0:plain.length() - check_len]
  let check = plain[plain.length() - check_len:plain.length()]
  if key.s2k_usage == 254 {
    let want = @primitives.Sha1.digest(material.exact_view())
    guard @primitives.ct_equal(want.exact_view(), check.exact_view()) else {
      @error.fail("api: wrong passphrase (SHA-1 check failed)")
    }
  } else {
    let want = @packet.session_key_checksum(material.exact_view())
    let got = (check[0].to_int() << 8) | check[1].to_int()
    guard want == got else {
      @error.fail("api: wrong passphrase (checksum failed)")
    }
  }
  @packet.SecretKeyPacket::{
    public: key.public,
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: material.to_owned(),
    dummy: false,
  }
}

///|
/// Protect the secret material with a passphrase: AES-256 CFB with an
/// iterated+salted S2K over SHA-256 and a SHA-1 check (usage 254). This is
/// the v4-compatible shape GnuPG 2.4 reads; use `PrivateKey::lock_argon2`
/// for the RFC 9580 recommendation.
fn lock_secret_key(
  key : @packet.SecretKeyPacket,
  passphrase : String,
) -> @packet.SecretKeyPacket raise {
  guard key.s2k_usage == 0 else { @error.fail("api: key is already locked") }
  let salt = @primitives.random_bytes(@s2k.SALT_SIZE)
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    salt,
    @s2k.encode_count(S2K_COUNT_TARGET),
  )
  let kek = s2k.derive_key(@primitives.utf8_bytes(passphrase).exact_view(), 32)
  let bc = @primitives.new_block_cipher(@primitives.Aes256, kek.exact_view())
  let iv = @primitives.random_bytes(16)
  let material = key.secret_material
  let check = @primitives.Sha1.digest(material.exact_view())
  let plain = material.add(check)
  let ciphertext = @cipher.cfb_encrypt(bc, iv.exact_view(), plain.exact_view())
  let spec_w = @packet.Writer::new()
  spec_w.bytes(s2k.encode().exact_view())
  @packet.SecretKeyPacket::{
    public: key.public,
    s2k_usage: 254,
    cipher_algo: @primitives.Aes256.number(),
    aead_algo: 0,
    s2k_spec: spec_w.to_bytes(),
    iv,
    secret_material: ciphertext,
    dummy: false,
  }
}

///|
/// Protect the secret material with Argon2id + AEAD (S2K usage octet 253,
/// RFC 9580 §3.7.1.4/§5.5.3): AES-256 in OCB mode, the Argon2 tag stretched
/// through HKDF-SHA256 for key separation, and the public key fields as AEAD
/// associated data. Defaults (t=3, p=4, m=2^16 KiB) match go-crypto and the
/// gopenpgp RFC 9580 profile.
fn lock_secret_key_argon2(
  key : @packet.SecretKeyPacket,
  passphrase : String,
  tag : Int32,
  passes : Int32,
  parallelism : Int32,
  memory_exp : Int32,
) -> @packet.SecretKeyPacket raise {
  guard key.s2k_usage == 0 else { @error.fail("api: key is already locked") }
  let salt = @primitives.random_bytes(@s2k.ARGON2_SALT_SIZE)
  let s2k : @s2k.S2k = @s2k.Argon2(salt, passes, parallelism, memory_exp)
  let spec = s2k.encode() // validates the parameter domain
  let algo = @primitives.Aes256
  let cipher_algo = algo.number()
  let aead_algo = @cipher.Ocb.number()
  let nonce_len = @cipher.Ocb.iv_length()
  if key.public.version() >= 6 {
    // The v6 parameter count is a single octet (RFC 9580 §5.5.3).
    guard 3 + spec.length() + nonce_len <= 0xFF else {
      @error.fail("api: v6 AEAD secret key parameters exceed one octet")
    }
  }
  let kek = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    algo.key_size(),
  )
  let info = Bytes::from_array([
    tag.to_byte(),
    key.public.version().to_byte(),
    cipher_algo.to_byte(),
    aead_algo.to_byte(),
  ])
  let dek = @primitives.hkdf_sha256(kek, Bytes::new(0), info, algo.key_size())
  let bc = @primitives.new_block_cipher(algo, dek.exact_view())
  let ad = secret_key_associated_data(key, tag)
  let nonce = @primitives.random_bytes(nonce_len)
  let ciphertext = @cipher.ocb_encrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    key.secret_material.exact_view(),
  )
  @packet.SecretKeyPacket::{
    public: key.public,
    s2k_usage: 253,
    cipher_algo,
    aead_algo,
    s2k_spec: spec,
    iv: nonce,
    secret_material: ciphertext,
    dummy: false,
  }
}

///|
/// Unlock the primary key (and its subkey) of a transferable private key
/// with a passphrase. Returns a copy with plaintext secret material.
/// Handles both the CFB (254/255) and the AEAD + Argon2 (253) protections.
pub fn PrivateKey::unlock(
  self : PrivateKey,
  passphrase : String,
  argon2_max_memory_kib~ : Int32 = @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
) -> PrivateKey raise {
  let subkeys : Array[SecretSubkeyCert] = []
  for c in self.subkeys {
    subkeys.push(SecretSubkeyCert::{
      secret: unlock_secret_key(
        c.secret,
        passphrase,
        0xC7,
        argon2_max_memory_kib,
      ),
      binding: c.binding,
      revocation: c.revocation,
    })
  }
  {
    primary: unlock_secret_key(
      self.primary,
      passphrase,
      0xC5,
      argon2_max_memory_kib,
    ),
    user_ids: self.user_ids,
    direct_signature: self.direct_signature,
    subkeys,
    revocations: self.revocations,
  }
}

///|
/// Protect every secret component with a passphrase (usage 254, CFB +
/// SHA-1), the shape GnuPG 2.4 interoperates with.
pub fn PrivateKey::lock(
  self : PrivateKey,
  passphrase : String,
) -> PrivateKey raise {
  let subkeys : Array[SecretSubkeyCert] = []
  for c in self.subkeys {
    subkeys.push(SecretSubkeyCert::{
      secret: lock_secret_key(c.secret, passphrase),
      binding: c.binding,
      revocation: c.revocation,
    })
  }
  {
    primary: lock_secret_key(self.primary, passphrase),
    user_ids: self.user_ids,
    direct_signature: self.direct_signature,
    subkeys,
    revocations: self.revocations,
  }
}

///|
/// Protect every secret component with Argon2id + AES-256/OCB (S2K usage
/// octet 253) — the RFC 9580 recommendation, and what the gopenpgp
/// RFC 9580 profile produces. `memory_exp` is the exponent of the memory
/// size in KiB (default 16 → 64 MiB); `passes` and `parallelism` default to
/// go-crypto's t=3, p=4.
pub fn PrivateKey::lock_argon2(
  self : PrivateKey,
  passphrase : String,
  passes~ : Int32 = 3,
  parallelism~ : Int32 = 4,
  memory_exp~ : Int32 = 16,
) -> PrivateKey raise {
  let subkeys : Array[SecretSubkeyCert] = []
  for c in self.subkeys {
    subkeys.push(SecretSubkeyCert::{
      secret: lock_secret_key_argon2(
        c.secret,
        passphrase,
        0xC7,
        passes,
        parallelism,
        memory_exp,
      ),
      binding: c.binding,
      revocation: c.revocation,
    })
  }
  {
    primary: lock_secret_key_argon2(
      self.primary,
      passphrase,
      0xC5,
      passes,
      parallelism,
      memory_exp,
    ),
    user_ids: self.user_ids,
    direct_signature: self.direct_signature,
    subkeys,
    revocations: self.revocations,
  }
}

///|
/// True when any secret component (primary key or a subkey) is still
/// passphrase-protected. `unlock` unlocks all components together and
/// gopenpgp's `IsLocked` uses the same "any component" semantics, so
/// looking at the primary alone misreports a key whose subkey is the
/// protected one.
pub fn PrivateKey::is_locked(self : PrivateKey) -> Bool {
  if self.primary.s2k_usage != 0 {
    return true
  }
  for c in self.subkeys {
    if c.secret.s2k_usage != 0 {
      return true
    }
  }
  false
}

///|
/// True when any secret component uses the RFC 9580 AEAD protection
/// (S2K usage octet 253).
pub fn PrivateKey::is_aead_protected(self : PrivateKey) -> Bool {
  if self.primary.s2k_usage == 253 {
    return true
  }
  for c in self.subkeys {
    if c.secret.s2k_usage == 253 {
      return true
    }
  }
  false
}
