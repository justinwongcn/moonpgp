///|
/// Decrypt (unlock) the secret material of a v4 key packet in place.
/// Supports S2K usage 254 (SHA-1 check) and 255 / legacy cipher-id (2-octet
/// checksum) with AES ciphers. The result carries usage 0 plaintext
/// material.
pub fn unlock_secret_key(
  key : @packet.SecretKeyPacket,
  passphrase : String,
) -> @packet.SecretKeyPacket raise {
  guard key.s2k_usage != 0 else { key }
  guard !key.dummy else {
    raise @error.PgpError::PgpError(
      msg="api: secret material is a GnuPG dummy (moved to a smartcard)",
    )
  }
  guard key.cipher_algo == 7 || key.cipher_algo == 8 || key.cipher_algo == 9 else {
    raise @error.PgpError::PgpError(
      msg="api: unsupported protection cipher \{key.cipher_algo}",
    )
  }
  let algo = @error.require(
    @primitives.cipher_algo_of_number(key.cipher_algo),
    "api: unsupported protection cipher",
  )
  let s2k = (@s2k.parse(key.s2k_spec.exact_view()) catch {
      _ => raise @error.PgpError::PgpError(msg="api: bad S2K in locked key")
    }).0
  let kek = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    algo.key_size(),
  )
  let bc = @primitives.new_block_cipher(algo, kek.exact_view())
  let plain = @cipher.cfb_decrypt(
    bc,
    key.iv.exact_view(),
    key.secret_material.exact_view(),
  ) catch {
    _ =>
      raise @error.PgpError::PgpError(msg="api: secret key decryption failed")
  }
  // Split off the trailing check: 20-byte SHA-1 (usage 254) or 2-byte sum.
  let check_len : Int = if key.s2k_usage == 254 { 20 } else { 2 }
  guard plain.length() > check_len else {
    raise @error.PgpError::PgpError(
      msg="api: decrypted secret material too short",
    )
  }
  let material = plain[0:plain.length() - check_len]
  let check = plain[plain.length() - check_len:plain.length()]
  if key.s2k_usage == 254 {
    let want = @primitives.Sha1.digest(material.exact_view())
    guard @primitives.ct_equal(want.exact_view(), check.exact_view()) else {
      raise @error.PgpError::PgpError(
        msg="api: wrong passphrase (SHA-1 check failed)",
      )
    }
  } else {
    let want = @packet.session_key_checksum(material.exact_view())
    let got = (check[0].to_int() << 8) | check[1].to_int()
    guard want == got else {
      raise @error.PgpError::PgpError(
        msg="api: wrong passphrase (checksum failed)",
      )
    }
  }
  @packet.SecretKeyPacket::{
    public: key.public,
    s2k_usage: 0,
    cipher_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: material.to_owned(),
    dummy: false,
  }
}

///|
/// Protect the secret material with a passphrase: AES-256 CFB with an
/// iterated+salted S2K over SHA-256 and a SHA-1 check (usage 254).
pub fn lock_secret_key(
  key : @packet.SecretKeyPacket,
  passphrase : String,
) -> @packet.SecretKeyPacket raise {
  guard key.s2k_usage == 0 else {
    raise @error.PgpError::PgpError(msg="api: key is already locked")
  }
  let salt = @primitives.random_bytes(@s2k.SALT_SIZE)
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    salt,
    @s2k.encode_count(1024 * 1024),
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
    s2k_spec: spec_w.to_bytes(),
    iv,
    secret_material: ciphertext,
    dummy: false,
  }
}

///|
/// Unlock the primary key (and its subkey) of a transferable private key
/// with a passphrase. Returns a copy with plaintext secret material.
pub fn PrivateKey::unlock(
  self : PrivateKey,
  passphrase : String,
) -> PrivateKey raise {
  {
    primary: unlock_secret_key(self.primary, passphrase),
    user_id: self.user_id,
    self_signature: self.self_signature,
    encryption_subkey: match self.encryption_subkey {
      Some(sk) => Some(unlock_secret_key(sk, passphrase))
      None => None
    },
    subkey_binding: self.subkey_binding,
  }
}

///|
/// Protect every secret component with a passphrase.
pub fn PrivateKey::lock(
  self : PrivateKey,
  passphrase : String,
) -> PrivateKey raise {
  {
    primary: lock_secret_key(self.primary, passphrase),
    user_id: self.user_id,
    self_signature: self.self_signature,
    encryption_subkey: match self.encryption_subkey {
      Some(sk) => Some(lock_secret_key(sk, passphrase))
      None => None
    },
    subkey_binding: self.subkey_binding,
  }
}

///|
/// True when the primary key's secret material is still encrypted.
pub fn PrivateKey::is_locked(self : PrivateKey) -> Bool {
  self.primary.s2k_usage != 0
}
