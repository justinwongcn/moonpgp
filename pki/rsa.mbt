///|
/// RSA (RFC 8017) for OpenPGP. Threat model (S05): every private-key
/// operation is plain big-integer modular exponentiation — CRT without
/// blinding, non-constant-time compare-free arithmetic — so per-operation
/// timing varies with the secret exponents. Remote attackers observe only
/// whole-operation latency over a network; the realistic exposure is a
/// LOCAL attacker sharing the host and measuring the process. MoonBit
/// core has no constant-time bignum, so this is a documented tradeoff.
/// This file is the replacement seam (same contract as `x25519.mbt`): a
/// hardened bignum (CRT blinding, constant-time Montgomery ladder) drops
/// in by rewriting `raw_decrypt` and `pkcs1_v15_sign` bodies only.

///|
/// RSA public key: modulus and public exponent. Value carrier,
/// deliberately `pub(all)` (policy note, HANDOFF 2026-10-06): the api
/// layer assembles these from parsed/generated wire material; the guarded,
/// invariant-checked surface is `@api.PrivateKey`/`PublicKey`.
pub(all) struct RsaPublicKey {
  n : BigInt
  e : BigInt
} derive(Debug)

///|
/// RSA private key with CRT parameters. Value carrier, deliberately
/// `pub(all)` (see RsaPublicKey).
pub(all) struct RsaPrivateKey {
  public : RsaPublicKey
  d : BigInt
  p : BigInt
  q : BigInt
  /// p^-1 mod q (OpenPGP MPI order for the `u` parameter).
  u : BigInt
} derive(Debug)

///|
/// OCTET length of the modulus (k in PKCS#1 terms).
pub fn RsaPublicKey::octet_length(self : RsaPublicKey) -> Int32 {
  (self.n.bit_length() + 7) / 8
}

///|
/// Raw RSA public operation: m^e mod n.
pub fn RsaPublicKey::raw_encrypt(self : RsaPublicKey, m : BigInt) -> BigInt {
  m.pow(self.e, modulus=self.n)
}

///|
/// Raw RSA private operation with CRT speedup: m = c^d mod n.
pub fn RsaPrivateKey::raw_decrypt(self : RsaPrivateKey, c : BigInt) -> BigInt {
  let one = BigInt::from_int(1)
  let p = self.p
  let q = self.q
  let dp = self.d.mod(p.sub(one))
  let dq = self.d.mod(q.sub(one))
  let m1 = c.pow(dp, modulus=p)
  let m2 = c.pow(dq, modulus=q)
  // Garner: m = m1 + p * ((m2 - m1) * u mod q) with u = p^-1 mod q.
  // core's `mod` truncates, so normalize the remainder into [0, q).
  let mut h = self.u.mul(m2.sub(m1)).mod(q)
  if h < BigInt::from_int(0) {
    h = h.add(q)
  }
  m1.add(h.mul(p))
}

///|
/// os2ip: octet string to integer.
pub fn os2ip(data : BytesView) -> BigInt {
  BigInt::from_octets(data, signum=1)
}

///|
/// i2osp: integer to fixed-width octet string.
pub fn i2osp(v : BigInt, length : Int32) -> Bytes {
  @primitives.pad_left(v.to_octets().exact_view(), length)
}

///|
/// RSAES-PKCS1-v1_5 encryption (RFC 8017 §7.2): EM = 00 02 PS 00 M with
/// random nonzero PS of at least 8 octets.
pub fn RsaPublicKey::pkcs1_v15_encrypt(
  self : RsaPublicKey,
  message : BytesView,
) -> Bytes raise {
  let k = self.octet_length()
  guard message.length() <= k - 11 else {
    @error.fail("rsa: message too long for \{k}-octet modulus")
  }
  let ps_len = k - 3 - message.length()
  let ps : Array[Byte] = []
  while ps.length() < ps_len {
    let b = @primitives.random_bytes(1)
    if b[0] != b'\x00' {
      ps.push(b[0])
    }
  }
  let w = @packet.Writer::new()
  w.u8(0)
  w.u8(2)
  w.bytes(Bytes::from_array(ps).exact_view())
  w.u8(0)
  w.bytes(message)
  let em = w.to_bytes()
  i2osp(self.raw_encrypt(os2ip(em.exact_view())), k)
}

///|
/// RSAES-PKCS1-v1_5 decryption. Validates the 00 02 PS(>=8 nonzero) 00
/// framing; a malformed ciphertext raises without leaking the payload.
pub fn RsaPrivateKey::pkcs1_v15_decrypt(
  self : RsaPrivateKey,
  ciphertext : BytesView,
) -> Bytes raise {
  let k = self.public.octet_length()
  guard ciphertext.length() == k else {
    @error.fail("rsa: ciphertext length mismatch")
  }
  let em = i2osp(self.raw_decrypt(os2ip(ciphertext)), k)
  guard em[0] == b'\x00' && em[1] == b'\x02' else {
    @error.fail("rsa: bad decryption block type")
  }
  // Find the 00 separator after at least 8 nonzero padding octets.
  let mut sep = -1
  for i in 2..<k {
    if em[i] == b'\x00' {
      sep = i
      break
    }
  }
  guard sep >= 10 else { @error.fail("rsa: malformed PKCS#1 padding") }
  em[sep + 1:k].to_owned()
}

///|
/// RSASSA-PKCS1-v1_5 signature over a prehashed digest (RFC 8017 §9.2):
/// EM = 00 01 FF..FF 00 || DigestInfo(hash || digest).
pub fn RsaPrivateKey::pkcs1_v15_sign(
  self : RsaPrivateKey,
  hash : @primitives.HashId,
  digest : BytesView,
) -> Bytes raise {
  guard digest.length() == hash.digest_size() else {
    @error.fail("rsa: digest size mismatch")
  }
  let k = self.public.octet_length()
  let digest_info = @primitives.concat2(hash.der_prefix(), digest)
  // EM: 00 01 (FF+)*(>=8) 00 DigestInfo
  let pad_len = k - digest_info.length() - 3
  guard pad_len >= 8 else { @error.fail("rsa: RSA modulus too small") }
  let w = @packet.Writer::new()
  w.u8(0)
  w.u8(1)
  for _ in 0..<pad_len {
    w.u8(255)
  }
  w.u8(0)
  w.bytes(digest_info.exact_view())
  let em = w.to_bytes()
  i2osp(os2ip(em.exact_view()).pow(self.d, modulus=self.public.n), k)
}

///|
/// RSASSA-PKCS1-v1_5 verification: re-encode and compare exactly.
pub fn RsaPublicKey::pkcs1_v15_verify(
  self : RsaPublicKey,
  hash : @primitives.HashId,
  digest : BytesView,
  signature : BytesView,
) -> Bool raise {
  guard digest.length() == hash.digest_size() else {
    @error.fail("rsa: digest size mismatch")
  }
  let k = self.octet_length()
  // The wire MPI of a signature may have lost leading zero octets; the
  // value itself is what matters, so pad back to k before checking.
  guard signature.length() <= k else { return false }
  let s = os2ip(@primitives.pad_left(signature, k).exact_view())
  guard s < self.n else { return false }
  let em = i2osp(s.pow(self.e, modulus=self.n), k)
  let digest_info = @primitives.concat2(hash.der_prefix(), digest)
  let pad_len = k - digest_info.length() - 3
  guard pad_len >= 8 else { return false }
  let w = @packet.Writer::new()
  w.u8(0)
  w.u8(1)
  for _ in 0..<pad_len {
    w.u8(255)
  }
  w.u8(0)
  w.bytes(digest_info.exact_view())
  @primitives.ct_equal(em.exact_view(), w.to_bytes().exact_view())
}

///|
/// Generate an RSA key pair whose modulus has `bits` bits with public
/// exponent 65537. Primality uses Miller-Rabin with 40 random bases per
/// candidate after trial division.
pub fn generate_rsa_key(bits~ : Int32) -> RsaPrivateKey raise {
  // RFC 9580 §12.4: an implementation MUST NOT generate keys below 3072
  // bits and MUST NOT encrypt, sign or verify below 2048; 2048 is the
  // absolute floor we accept for explicit opt-in (S12).
  guard bits >= 2048 else {
    @error.fail("rsa: refusing to generate keys under 2048 bits")
  }
  guard bits % 2 == 0 else { @error.fail("rsa: bit count must be even") }
  let e = BigInt::from_int(65537)
  // Resample BOTH primes each round: with a fixed p near the top of the
  // range, |p - q| >= min_diff would be nearly unreachable for q alone.
  let min_diff = BigInt::from_int(1).shl(bits / 2 - 64)
  let mut p = random_prime(bits / 2, coprime=e, rounds=40)
  let mut q = random_prime(bits / 2, coprime=e, rounds=40)
  let mut guard_count = 0
  let mut too_close = true
  while too_close {
    let diff = if p.compare(q) == -1 { q.sub(p) } else { p.sub(q) }
    too_close = diff.compare(min_diff) == -1
    if !too_close {
      break
    }
    p = random_prime(bits / 2, coprime=e, rounds=40)
    q = random_prime(bits / 2, coprime=e, rounds=40)
    guard_count = guard_count + 1
    guard guard_count < 100 else { @error.fail("rsa: prime generation stuck") }
  }
  let n = p.mul(q)
  let one = BigInt::from_int(1)
  // phi = (p-1)(q-1); d = e^-1 mod phi (also valid mod lambda for e=65537).
  let phi = p.sub(one).mul(q.sub(one))
  let d = mod_inverse(e, phi)
  let u = mod_inverse(p, q)
  RsaPrivateKey::{ public: { n, e, }, d, p, q, u, }
}

///|
pub extend RsaPrivateKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RsaPublicKey with @moonbitlang/core/debug.Debug::{to_repr}
