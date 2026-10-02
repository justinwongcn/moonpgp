///|
/// gopenpgp-style entry point: `pgp().encryption()...`.
pub fn pgp() -> Pgp {
  Pgp::{ }
}

///|
pub struct Pgp {}

///|
/// Builder for encryption.
pub(all) struct EncryptionBuilder {
  priv passwords : Array[String]
  priv recipients : Array[PublicKey]
  priv signer : PrivateKey?
  priv file_name : String
}

///|
pub fn Pgp::encryption(self : Pgp) -> EncryptionBuilder {
  EncryptionBuilder::{
    passwords: [],
    recipients: [],
    signer: None,
    file_name: "message.txt",
  }
}

///|
pub fn EncryptionBuilder::password(
  self : EncryptionBuilder,
  pass : String,
) -> EncryptionBuilder {
  let passwords = self.passwords
  passwords.push(pass)
  { ..self, passwords, }
}

///|
pub fn EncryptionBuilder::recipient(
  self : EncryptionBuilder,
  key : PublicKey,
) -> EncryptionBuilder {
  let recipients = self.recipients
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
  fn(data : BytesView) -> String raise {
    if not(recipients.is_empty()) {
      // Public-key path; wrap an inline signature when a signer is set.
      let armored = match signer {
        Some(sk) => sign_and_encrypt(data, sk, recipients)
        None => encrypt_to_recipients(data, recipients, file_name~)
      }
      return armored
    }
    if not(passwords.is_empty()) {
      return encrypt_with_password(data, passwords[0], file_name~)
    }
    raise @error.PgpError::PgpError(
      msg="api: encryption requires a password or a recipient",
    )
  }
}

///|
/// Builder for decryption.
pub(all) struct DecryptionBuilder {
  priv passwords : Array[String]
  priv private_keys : Array[PrivateKey]
  priv verifiers : Array[PublicKey]
}

///|
pub fn Pgp::decryption(self : Pgp) -> DecryptionBuilder {
  DecryptionBuilder::{ passwords: [], private_keys: [], verifiers: [], }
}

///|
pub fn DecryptionBuilder::password(
  self : DecryptionBuilder,
  pass : String,
) -> DecryptionBuilder {
  let passwords = self.passwords
  passwords.push(pass)
  { ..self, passwords, }
}

///|
pub fn DecryptionBuilder::decryption_key(
  self : DecryptionBuilder,
  key : PrivateKey,
) -> DecryptionBuilder {
  let private_keys = self.private_keys
  private_keys.push(key)
  { ..self, private_keys, }
}

///|
pub fn DecryptionBuilder::verification_key(
  self : DecryptionBuilder,
  key : PublicKey,
) -> DecryptionBuilder {
  let verifiers = self.verifiers
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
  fn(message : String) -> DecryptResult raise {
    if not(private_keys.is_empty()) {
      let (d, status) = decrypt_and_verify_list(
        message, private_keys, verifiers,
      )
      return match status {
        Ok => Verified(d)
        Failed => SignatureError(d)
        // No verifier matched, or the message carried no signature.
        NoVerifier | NotSigned => Data(d)
      }
    }
    if not(passwords.is_empty()) {
      return Data(decrypt_with_password(message, passwords[0]))
    }
    raise @error.PgpError::PgpError(
      msg="api: decryption requires a password or a private key",
    )
  }
}

///|
/// decrypt_and_verify over a list of candidate keys.
fn decrypt_and_verify_list(
  message : String,
  keys : Array[PrivateKey],
  verifiers : Array[PublicKey],
) -> (Bytes, VerifyStatus) raise {
  if keys.length() == 1 && verifiers.length() == 1 {
    decrypt_and_verify(message, keys, Some(verifiers[0]))
  } else if keys.length() == 1 {
    decrypt_and_verify(message, keys, None)
  } else {
    // Try each key until one matches.
    let mut last_error : String? = None
    for key in keys {
      match (try? decrypt_and_verify(message, [key], None)) {
        Ok((d, s)) => return (d, s)
        Err(e) => last_error = Some(e.to_string())
      }
    }
    match last_error {
      Some(msg) => raise @error.PgpError::PgpError(msg~)
      None => raise @error.PgpError::PgpError(msg="api: decryption failed")
    }
  }
}

///|
/// Builder for key generation.
pub(all) struct KeyGenBuilder {
  priv user_id : String
  priv bits : Int
}

///|
pub fn Pgp::key_generation(self : Pgp) -> KeyGenBuilder {
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
  bits : Int,
) -> KeyGenBuilder {
  { ..self, bits, }
}

///|
pub fn KeyGenBuilder::generate(self : KeyGenBuilder) -> PrivateKey raise {
  guard self.user_id != "" else {
    raise @error.PgpError::PgpError(msg="api: key generation needs a user id")
  }
  generate_key(self.user_id, bits=self.bits)
}
