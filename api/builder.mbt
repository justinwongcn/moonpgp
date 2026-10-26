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
  /// v6-shape passphrase recipients (task 3): each gets its own v6 SKESK
  /// under the shared session key. Mutually exclusive with `passwords`
  /// (one message cannot mix ESK generations).
  priv passwords_v6 : Array[V6Password]
  priv recipients : Array[PublicKey]
  priv signer : PrivateKey?
  priv file_name : String
  priv compress : @compress.CompressedAlgo?
}

///|
/// Start building an encryption (password or public-key recipients). This
/// is the recommended entry point for new code: chain `.password`,
/// `.password_v6`, `.recipient`, `.sign_with`, `.file_name` and `.compress`,
/// then `finish` returns a reusable sealing closure.
///
/// # Example
///
/// ```mbt check
/// test "builder chain seals a payload" {
///   let seal = @api.pgp()
///     .encryption()
///     .password("hunter2")
///     .file_name("msg.txt")
///     .finish()
///   let armored = seal(b"payload")
///   inspect(armored.has_prefix("-----BEGIN PGP MESSAGE-----"), content="true")
/// }
/// ```
pub fn Pgp::encryption(_self : Pgp) -> EncryptionBuilder {
  EncryptionBuilder::{
    passwords: [],
    passwords_v6: [],
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
/// Add a passphrase recipient in the RFC 9580 v6 shape (v6 SKESK + v2
/// SEIPD; task 3): Argon2id S2K by default — set `argon2=false` for the
/// cheaper iterated+salted SHA-256. Cannot be combined with `password`
/// (v4 shape) in one message.
pub fn EncryptionBuilder::password_v6(
  self : EncryptionBuilder,
  pass : String,
  aead~ : @cipher.AeadMode = @cipher.Ocb,
  argon2~ : Bool = true,
  passes~ : Int32 = 3,
  parallelism~ : Int32 = 4,
  memory_exp~ : Int32 = 16,
) -> EncryptionBuilder {
  let passwords_v6 = self.passwords_v6.copy()
  passwords_v6.push(V6Password::{
    passphrase: pass,
    aead,
    argon2,
    passes,
    parallelism,
    memory_exp,
  })
  { ..self, passwords_v6, }
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
  let passwords_v6 = self.passwords_v6
  let recipients = self.recipients
  let signer = self.signer
  let file_name = self.file_name
  let compress = self.compress
  fn(data : BytesView) -> String raise {
    if !recipients.is_empty() {
      // Public-key path; wrap an inline signature when a signer is set.
      // `file_name` applies to both branches (N9).
      let armored = match signer {
        Some(sk) =>
          sign_and_encrypt(data, sk, recipients, file_name~, compress?)
        None => encrypt_to_recipients(data, recipients, file_name~, compress?)
      }
      return armored
    }
    if !passwords_v6.is_empty() {
      guard passwords.is_empty() else {
        @error.fail(
          "api: cannot mix v4 and v6 passphrase shapes in one message",
        )
      }
      return seal_skesks_v6_with_passwords(
        data,
        passwords_v6,
        file_name~,
        compress?,
      )
    }
    if !passwords.is_empty() {
      // Every supplied passphrase gets its own SKESK over one shared
      // session key (N4) instead of silently dropping all but the first.
      return seal_skesks_with_passwords(data, passwords, file_name~, compress?)
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
      // Try each passphrase in turn (N4): the message may have been
      // sealed to several and the matching SKESK need not be first.
      let mut last_error : String? = None
      for pass in passwords {
        let data : Bytes? = Some(
          decrypt_with_password(message, pass, max_decompressed~),
        ) catch {
          e => {
            last_error = Some(e.to_string())
            None
          }
        }
        if data is Some(d) {
          return Data(d)
        }
      }
      match last_error {
        Some(msg) => @error.fail(msg)
        None => @error.fail("api: decryption failed")
      }
    }
    @error.fail("api: decryption requires a password or a private key")
  }
}

///|
/// decrypt_and_verify over a list of candidate keys: every key is tried
/// until one decrypts, and — when verifiers were supplied — every
/// verifier is consulted on that successful decryption, keeping the
/// best-ranked status (N5: verifiers used to be silently dropped the
/// moment more than one key was given).
fn decrypt_and_verify_list(
  message : String,
  keys : Array[PrivateKey],
  verifiers : Array[PublicKey],
  max_decompressed : Int32,
) -> (Bytes, VerifyStatus) raise {
  let mut last_error : String? = None
  for key in keys {
    if verifiers.is_empty() {
      let pair : (Bytes, VerifyStatus)? = Some(
        decrypt_and_verify(message, [key], None, max_decompressed~),
      ) catch {
        e => {
          last_error = Some(e.to_string())
          None
        }
      }
      if pair is Some(result) {
        return result
      }
    } else {
      let mut best : (Bytes, VerifyStatus)? = None
      for v in verifiers {
        let pair : (Bytes, VerifyStatus)? = Some(
          decrypt_and_verify(message, [key], Some(v), max_decompressed~),
        ) catch {
          e => {
            last_error = Some(e.to_string())
            None
          }
        }
        if pair is Some((d, s)) {
          let take = match best {
            Some((_, cur)) => status_rank(s) > status_rank(cur)
            None => true
          }
          if take {
            best = Some((d, s))
          }
        }
      }
      if best is Some(result) {
        return result
      }
    }
  }
  match last_error {
    Some(msg) => @error.fail(msg)
    None => @error.fail("api: decryption failed")
  }
}

///|
/// Ranking across candidate verifiers (gopenpgp's
/// prioritizeSignatureErrors): a verified signature outranks everything;
/// among failures, verification rejections outweigh missing signatures.
fn status_rank(status : VerifyStatus) -> Int32 {
  match status {
    Ok => 4
    Failed | KeyRevoked | Expired => 3
    NoVerifier => 2
    NotSigned => 1
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
