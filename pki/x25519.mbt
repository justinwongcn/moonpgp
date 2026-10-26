///|
/// X25519 for the OpenPGP ECDH algorithm (ID 18) over Curve25519Legacy,
/// RFC 7748. The arithmetic lives in `curve25519.mbt` on `@bigint`.
/// Scalars and points are 32-octet little-endian "native" values
/// (RFC 7748); the OpenPGP wire forms (MPI point, big-endian secret MPI)
/// are handled at the packet/key layers. This file is the replacement
/// seam: an official `x/crypto` X25519 drops in by rewriting these
/// function bodies.

///|
/// The Curve25519Legacy curve OID for OpenPGP: 1.3.6.1.4.1.3029.1.5.1
/// (RFC 9580 §9.2), length-prefixed on the wire (10 octets of OID).
pub fn curve25519_oid() -> Bytes {
  Bytes::from_array([
    0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
  ])
}

///|
/// Value carrier, deliberately `pub(all)`: the api layer assembles these
/// from parsed/generated wire material and reads the fields directly.
/// The guarded, invariant-checked surface is `@api.PrivateKey`/`PublicKey`;
/// treat this struct as plain data (policy note, HANDOFF 2026-10-06).
pub(all) struct X25519SecretKey {
  /// 32-octet little-endian scalar, already clamped.
  scalar : Bytes
  /// 32-octet little-endian public key.
  public : Bytes
} derive(Debug)

///|
fn x25519_clamp(scalar : BytesView) -> Bytes raise {
  guard scalar.length() == 32 else {
    @error.malformed("pki: X25519 scalar must be 32 octets")
  }
  let out = to_byte_array(scalar)
  out[0] = (out[0].to_int() & 248).to_byte()
  out[31] = ((out[31].to_int() & 127) | 64).to_byte()
  Bytes::from_array(out)
}

///|
/// Derive the public key (and normalized secret) from a raw scalar. The
/// input is clamped before use, matching RFC 7748 §6.1 key generation.
pub fn x25519_public_of_scalar(scalar : BytesView) -> X25519SecretKey raise {
  let clamped = x25519_clamp(scalar)
  let u_base = Bytes::from_array([
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
  ])
  let public = mont_ladder(
    clamped.exact_view(),
    u_base.exact_view(),
    c25519_p(),
  )
  X25519SecretKey::{ scalar: clamped, public: bigint_to_le_bytes(public, 32), }
}

///|
/// Generate a fresh X25519 key pair from platform entropy.
pub fn x25519_generate() -> X25519SecretKey raise {
  x25519_public_of_scalar(@primitives.random_bytes(32).exact_view())
}

///|
/// Decode a Curve25519Legacy secret-key MPI value (a big-endian integer
/// of the clamped scalar, RFC 9580 §5.5.5.6.1.1) into the native
/// little-endian form and derive the public key.
pub fn x25519_secret_of_wire_mpi(
  mpi_value : BytesView,
) -> X25519SecretKey raise {
  // Tolerate a stripped leading zero octet (MPI semantics).
  guard mpi_value.length() <= 32 else {
    @error.malformed("pki: Curve25519Legacy secret MPI must be 32 octets")
  }
  let full = @primitives.pad_left(mpi_value, 32)
  let le : Array[Byte] = []
  for i in 0..<32 {
    le.push(full[31 - i])
  }
  x25519_public_of_scalar(Bytes::from_array(le).exact_view())
}

///|
/// The raw big-endian MPI value for this secret key's wire form
/// (255-bit clamped scalar, RFC 9580 §5.5.5.6.1.1).
pub fn X25519SecretKey::wire_mpi(self : X25519SecretKey) -> Bytes {
  let be : Array[Byte] = [b'\x00', b'\xFF']
  for i in 0..<32 {
    be.push(self.scalar[31 - i])
  }
  Bytes::from_array(be)
}

///|
/// Diffie-Hellman shared secret (32-octet little-endian). Raises on an
/// all-zero output (low-order peer point).
pub fn x25519_shared_secret(
  scalar : BytesView,
  peer_public : BytesView,
) -> Bytes raise {
  guard scalar.length() == 32 && peer_public.length() == 32 else {
    @error.malformed("pki: X25519 inputs must be 32 octets each")
  }
  let clamped = x25519_clamp(scalar)
  let z = mont_ladder(clamped.exact_view(), peer_public, c25519_p())
  bigint_to_le_bytes(z, 32)
}

///|
/// ECDH key derivation (RFC 9580 §11.4): SHA-256 single-step Concat KDF
/// over 0x00000001 || Z || Param, truncated to `bits` bits. Used to
/// derive the AES key-encryption key for §11.5 key wrapping.
pub fn ecdh_kdf_sha256(
  z : BytesView,
  param : BytesView,
  bits : Int32,
) -> Bytes raise {
  guard bits % 8 == 0 && bits > 0 else {
    @error.fail("pki: bad KDF output size \{bits}")
  }
  let w : Array[Byte] = [b'\x00', b'\x00', b'\x00', b'\x01']
  for b in z {
    w.push(b)
  }
  for b in param {
    w.push(b)
  }
  let h = @primitives.Sha256.digest(Bytes::from_array(w).exact_view())
  h[0:bits / 8].to_owned()
}

///|
/// The 20-octet "Anonymous Sender    " KDF parameter string
/// (RFC 9580 §11.5).
pub fn ecdh_anonymous_sender() -> Bytes {
  @primitives.utf8_bytes("Anonymous Sender    ")
}

///|
pub extend X25519SecretKey with @moonbitlang/core/debug.Debug::{to_repr}
