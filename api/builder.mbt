///|
/// gopenpgp-style entry point: `pgp().encryption()...`.
pub fn pgp() -> Pgp {
  Pgp::{ }
}

///|
/// Top-level facade for the builder API. Stateless — every operation is
/// configured through one of the three builders below.
pub struct Pgp {}

///|
/// Builder for encryption. Fields are private; instances are created via
/// `Pgp::encryption` and evolve through the chain methods.
pub struct EncryptionBuilder {
  priv passwords : Array[String]
  priv recipients : Array[PublicKey]
  priv signer : PrivateKey?
  priv file_name : String
  priv compress : @compress.CompressedAlgo?
}

///|
/// Start building an encryption (password or public-key recipients).
pub fn Pgp::encryption(_self : Pgp) -> EncryptionBuilder {
  EncryptionBuilder::{
    passwords: [],
    recipients: [],
    signer: None,
    file_name: "message.txt",
    compress: None,
  }
}

///|
/// Compress the payload before encryption (ZIP or ZLIB; M4). Off by
/// default — the historical behavior of this library — and only honored
/// by the encryption entry points.
pub fn EncryptionBuilder::compress(
  self : EncryptionBuilder,
  algo : @compress.CompressedAlgo,
) -> EncryptionBuilder {
  { ..self, compress: Some(algo), }
}

///|
pub fn EncryptionBuilder::password(
  self : EncryptionBuilder,
  pass : String,
) -> EncryptionBuilder {
  let passwords = self.passwords.copy()
  passwords.push(pass)
  { ..self, passwords, }
}

///|
pub fn EncryptionBuilder::recipient(
  self : EncryptionBuilder,
  key : PublicKey,
) -> EncryptionBuilder {
  let recipients = self.recipients.copy()
  recipients.push(key)
  { ..self, recipients, }
}

///|
pub fn EncryptionBuilder::sign_with(
  self : EncryptionBuilder,
  key : PrivateKey,
) -> EncryptionBuilder {
  { ..self, signer: Some(key), }
}

///|
pub fn EncryptionBuilder::file_name(
  self : EncryptionBuilder,
  name : String,
) -> EncryptionBuilder {
  { ..self, file_name: name, }
}

///|
/// Finish the builder: at least one password or recipient is required.
/// Returns a closure that encrypts arbitrary payloads with this setup.
pub fn EncryptionBuilder::finish(
  self : EncryptionBuilder,
) -> (BytesView) -> String raise {
  let passwords = self.passwords
  let recipients = self.recipients
  let signer = self.signer
  let file_name = self.file_name
  let compress = self.compress
  fn(data : BytesView) -> String raise {
    if !recipients.is_empty() {
      // Public-key path; wrap an inline signature when a signer is set.
      let armored = match signer {
        Some(sk) => sign_and_encrypt(data, sk, recipients, compress?)
        None => encrypt_to_recipients(data, recipients, file_name~, compress?)
      }
      return armored
    }
    if !passwords.is_empty() {
      return encrypt_with_password(data, passwords[0], file_name~, compress?)
    }
    @error.fail("api: encryption requires a password or a recipient")
  }
}

///|
/// Builder for decryption.
pub struct DecryptionBuilder {
  priv passwords : Array[String]
  priv private_keys : Array[PrivateKey]
  priv verifiers : Array[PublicKey]
  priv max_decompressed : Int32
}

///|
/// Start building a decryption (private keys and optional verifiers).
pub fn Pgp::decryption(_self : Pgp) -> DecryptionBuilder {
  DecryptionBuilder::{
    passwords: [],
    private_keys: [],
    verifiers: [],
    max_decompressed: DEFAULT_MAX_DECOMPRESSED_BYTES,
  }
}

///|
/// Override the decompressed-payload ceiling (M4; default 512 MiB).
pub fn DecryptionBuilder::max_decompressed(
  self : DecryptionBuilder,
  limit : Int32,
) -> DecryptionBuilder {
  { ..self, max_decompressed: limit, }
}

///|
pub fn DecryptionBuilder::password(
  self : DecryptionBuilder,
  pass : String,
) -> DecryptionBuilder {
  let passwords = self.passwords.copy()
  passwords.push(pass)
  { ..self, passwords, }
}

///|
pub fn DecryptionBuilder::decryption_key(
  self : DecryptionBuilder,
  key : PrivateKey,
) -> DecryptionBuilder {
  let private_keys = self.private_keys.copy()
  private_keys.push(key)
  { ..self, private_keys, }
}

///|
pub fn DecryptionBuilder::verification_key(
  self : DecryptionBuilder,
  key : PublicKey,
) -> DecryptionBuilder {
  let verifiers = self.verifiers.copy()
  verifiers.push(key)
  { ..self, verifiers, }
}

///|
/// Outcome of a combined decrypt+verify: data plus signature status.
pub(all) enum DecryptResult {
  /// Data decrypted; the message carried no verifiable signature.
  Data(Bytes)
  /// Data decrypted and the inline signature verified.
  Verified(Bytes)
  /// Data decrypted but the inline signature failed.
  SignatureError(Bytes)
} derive(Debug)

///|
pub fn DecryptionBuilder::finish(
  self : DecryptionBuilder,
) -> (String) -> DecryptResult raise {
  let passwords = self.passwords
  let private_keys = self.private_keys
  let verifiers = self.verifiers
  let max_decompressed = self.max_decompressed
  fn(message : String) -> DecryptResult raise {
    if !private_keys.is_empty() {
      let (d, status) = decrypt_and_verify_list(
        message, private_keys, verifiers, max_decompressed,
      )
      return match status {
        Ok => Verified(d)
        Failed => SignatureError(d)
        // A valid-but-rejected signature (revoked or expired key) is still
        // a signature error, not a missing signature.
        KeyRevoked | Expired => SignatureError(d)
        // No verifier matched, or the message carried no signature.
        NoVerifier | NotSigned => Data(d)
      }
    }
    if !passwords.is_empty() {
      return Data(
        decrypt_with_password(message, passwords[0], max_decompressed~),
      )
    }
    @error.fail("api: decryption requires a password or a private key")
  }
}

///|
/// decrypt_and_verify over a list of candidate keys.
fn decrypt_and_verify_list(
  message : String,
  keys : Array[PrivateKey],
  verifiers : Array[PublicKey],
  max_decompressed : Int32,
) -> (Bytes, VerifyStatus) raise {
  if keys.length() == 1 && verifiers.length() == 1 {
    decrypt_and_verify(message, keys, Some(verifiers[0]), max_decompressed~)
  } else if keys.length() == 1 {
    decrypt_and_verify(message, keys, None, max_decompressed~)
  } else {
    // Try each key until one matches.
    let mut last_error : String? = None
    for key in keys {
      try {
        let (d, s) = decrypt_and_verify(message, [key], None, max_decompressed~)
        return (d, s)
      } catch {
        e => last_error = Some(e.to_string())
      }
    }
    match last_error {
      Some(msg) => @error.fail(msg)
      None => @error.fail("api: decryption failed")
    }
  }
}

///|
/// Builder for key generation.
pub struct KeyGenBuilder {
  priv user_id : String
  priv bits : Int32
}

///|
/// Start building a key generation (RSA by default; Ed25519 via
/// `generate_ed25519_key`).
pub fn Pgp::key_generation(_self : Pgp) -> KeyGenBuilder {
  KeyGenBuilder::{ user_id: "", bits: 3072, }
}

///|
pub fn KeyGenBuilder::add_user_id(
  self : KeyGenBuilder,
  user_id : String,
) -> KeyGenBuilder {
  { ..self, user_id, }
}

///|
pub fn KeyGenBuilder::rsa_bits(
  self : KeyGenBuilder,
  bits : Int32,
) -> KeyGenBuilder {
  { ..self, bits, }
}

///|
pub fn KeyGenBuilder::generate(self : KeyGenBuilder) -> PrivateKey raise {
  guard self.user_id != "" else {
    @error.fail("api: key generation needs a user id")
  }
  generate_key(self.user_id, bits=self.bits)
}

///|
pub extend DecryptResult with @moonbitlang/core/debug.Debug::{to_repr}
