///|
/// Root facade of `justinwongcn/moonpgp`: a single
/// `import "justinwongcn/moonpgp"` gives the complete high-level OpenPGP
/// workflow (`@moonpgp.generate_key`, `@moonpgp.encrypt_with_password`,
/// sign/verify, builders, key management). Every item is re-exported from
/// its owning public package, so methods resolve through the usual owner
/// loading and lower layers (`@packet`, `@pki`, `@armor`, ...) remain
/// directly importable for advanced use.
pub using @api {
  DEFAULT_MAX_DECOMPRESSED_BYTES,
  decrypt_and_verify,
  decrypt_binary_with_password,
  decrypt_binary_with_private_key,
  decrypt_to_session_key,
  decrypt_with_password,
  decrypt_with_private_key,
  encrypt_to_recipients,
  encrypt_to_session_key,
  encrypt_with_password,
  encrypt_with_password_argon2,
  encrypt_with_password_v6,
  generate_ed25519_key,
  generate_ed25519_v6_key,
  generate_ed25519_v6_key_with_signing_subkey,
  generate_key,
  generate_revocation_certificate,
  generate_session_key,
  pgp,
  revoke_key,
  revoke_subkey,
  recover_session_key_with_key,
  recover_session_key_with_password,
  sign_and_encrypt,
  sign_cleartext,
  sign_cleartext_with,
  sign_detached,
  sign_inline,
  verify_cleartext,
  verify_detached,
  verify_inline,
  verify_key_signature,
  type DecryptResult,
  type DecryptionBuilder,
  type EncryptionBuilder,
  type KeyGenBuilder,
  type KeyRing,
  type Pgp,
  type PrivateKey,
  type PublicKey,
  type RevocationReason,
  type SecretSubkeyCert,
  type SessionKey,
  type SubkeyCert,
  type UserIdBinding,
  type VerifyStatus,
}

///|
/// Option types that appear in `@api` signatures, re-exported so the bare
/// root import covers the whole main workflow (an `AeadMode` for
/// `encrypt_with_password_v6`, a `CompressedAlgo` for the encryption
/// builders, a `CipherAlgo` for session keys, a `HashId` for
/// `sign_cleartext_with`).
pub using @cipher {type AeadMode}

///|
pub using @compress {type CompressedAlgo}

///|
pub using @primitives {type CipherAlgo, type HashId}

///|
/// The error type raised throughout the module, re-exported so a bare root
/// import is enough to catch and branch on the failure classes
/// (`Malformed`, `Unsupported`, `WrongPassphrase`).
pub using @error {type PgpError}

///|
/// PGP/MIME high-level entry points, re-exported so the bare root import
/// also covers signing and verifying `multipart/signed` mail; the `mime`
/// package stays the home of the full parsing/assembly API.
pub using @mime {build_pgp_mime_signed, verify_pgp_mime_signed}
