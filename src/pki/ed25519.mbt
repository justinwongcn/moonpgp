///|
/// Ed25519 for the OpenPGP "EdDSA legacy" algorithm (ID 22, Ed25519 on
/// Curve25519), RFC 8032. The arithmetic lives in `curve25519.mbt` on
/// `@bigint`; only the OpenPGP-specific framing (OID, MPI, key structs)
/// appears here. This file is the replacement seam: an official
/// `x/crypto` Ed25519 drops in by rewriting these function bodies.

///|
/// The Ed25519Legacy curve OID for OpenPGP: 1.3.6.1.4.1.11591.15.1
/// (RFC 9580 §9.2), length-prefixed on the wire (9 octets of OID).
pub fn ed25519_oid() -> Bytes {
  Bytes::from_array([0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
}

///|
pub(all) struct Ed25519SecretKey {
  /// 32-octet seed.
  seed : Bytes
  /// 32-octet public key (compressed point).
  public : Bytes
} derive(Debug)

///|
/// Generate a fresh Ed25519 key pair from platform entropy.
pub fn ed25519_generate() -> Ed25519SecretKey raise {
  let seed = @primitives.random_bytes(32)
  ed25519_public_of_seed(seed.exact_view())
}

///|
/// Derive the 32-octet public key from a seed (RFC 8032 §5.1.5: the
/// clamped SHA-512 expansion, multiplied by the base point).
pub fn ed25519_public_of_seed(seed : BytesView) -> Ed25519SecretKey raise {
  guard seed.length() == 32 else {
    raise @error.PgpError::PgpError(msg="pki: Ed25519 seed must be 32 octets")
  }
  let ctx = ed25519_ctx()
  let (a, _prefix) = ed_expand_seed(seed)
  Ed25519SecretKey::{
    seed: seed.to_owned(),
    public: ed_encode(ed_scalar_mult(a, ctx.base, ctx), ctx),
  }
}

///|
/// Wrap a 32-octet public key. The bytes are NOT validated as a curve
/// point here; a malformed key makes `verify` return false instead of
/// failing at construction (same contract as the packet layer).
pub fn ed25519_public_key(bytes : BytesView) -> Ed25519PublicKeyValue raise {
  guard bytes.length() == 32 else {
    raise @error.PgpError::PgpError(
      msg="pki: Ed25519 public key must be 32 octets",
    )
  }
  Ed25519PublicKeyValue::{ bytes: bytes.to_owned(), }
}

///|
pub(all) struct Ed25519PublicKeyValue {
  bytes : Bytes
} derive(Debug)

///|
/// Sign `message` (for OpenPGP EdDSA legacy this is the digest) with pure
/// Ed25519 (RFC 8032 §5.1.6); returns the 64-octet signature (r || s).
/// The nonce is deterministic: r = SHA512(prefix || message) mod L.
/// Assumes `public` is the public key of `seed` — the pair is generated
/// together by `ed25519_generate` / `ed25519_public_of_seed`; a
/// mismatched combination yields signatures that fail verification.
pub fn Ed25519SecretKey::sign(
  self : Ed25519SecretKey,
  message : BytesView,
) -> Bytes raise {
  let ctx = ed25519_ctx()
  let (a, prefix) = ed_expand_seed(self.seed.exact_view())
  let r = le_bytes_to_bigint(
    @primitives.Sha512.digest(prefix.add(message.to_owned()).exact_view()),
  ).mod(ctx.l)
  let r_enc = ed_encode(ed_scalar_mult(r, ctx.base, ctx), ctx)
  let k = le_bytes_to_bigint(
    @primitives.Sha512.digest(
      r_enc.add(self.public).add(message.to_owned()).exact_view(),
    ),
  ).mod(ctx.l)
  let s = r.add(k.mul(a)).mod(ctx.l)
  r_enc.add(bigint_to_le_bytes(s, 32))
}

///|
/// Verify a 64-octet Ed25519 signature over `message` (RFC 8032 §5.1.7,
/// cofactored equation [8][S]B == [8]R + [8][k]A). Returns false on any
/// malformed encoding or failed equation instead of raising.
pub fn Ed25519PublicKeyValue::verify(
  self : Ed25519PublicKeyValue,
  message : BytesView,
  signature : BytesView,
) -> Bool raise {
  guard signature.length() == 64 else { return false }
  let ctx = ed25519_ctx()
  let a_pt = match ed_decode_opt(self.bytes.exact_view(), ctx) {
    Some(p) => p
    None => return false
  }
  let r_pt = match ed_decode_opt(signature[0:32], ctx) {
    Some(p) => p
    None => return false
  }
  let s = le_bytes_to_bigint(signature[32:64])
  guard s < ctx.l else { return false }
  let k = le_bytes_to_bigint(
    @primitives.Sha512.digest(
      signature[0:32]
      .to_owned()
      .add(self.bytes)
      .add(message.to_owned())
      .exact_view(),
    ),
  ).mod(ctx.l)
  let mut left = ed_scalar_mult(s, ctx.base, ctx)
  let mut right = ed_add(r_pt, ed_scalar_mult(k, a_pt, ctx), ctx)
  // Cofactor 8: three doublings on both sides.
  for _ in 0..<3 {
    left = ed_double(left, ctx)
    right = ed_double(right, ctx)
  }
  ed_equal(left, right, ctx)
}
