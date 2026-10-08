///|
/// String-to-Key derivations (RFC 9580 §3.7). PGP-wire material, never a
/// replaceable third-party concern.
pub(all) enum S2k {
  /// Usage type 0.
  Simple(@primitives.HashId)
  /// Usage type 1.
  Salted(@primitives.HashId, Bytes)
  /// Usage type 3.
  Iterated(@primitives.HashId, Bytes, Int)
  /// Usage type 4 (RFC 9580 §3.7.1.4): Argon2id. There is no hash-algorithm
  /// octet — the hash is BLAKE2b inside Argon2 — so the fields are the
  /// 16-octet salt, the number of passes `t`, the degree of parallelism
  /// `p`, and the memory exponent `encoded_m` (`m = 2^encoded_m` KiB).
  Argon2(Bytes, Int, Int, Int)
} derive(Eq, Debug)

///|
/// Salt length in octets for salted/iterated S2K.
pub const SALT_SIZE : Int = 8

///|
/// Salt length in octets for Argon2 S2K (RFC 9580 §3.7.1.4).
pub const ARGON2_SALT_SIZE : Int = 16

///|
/// Parse an S2K specifier from the front of `view`. Returns the specifier
/// and the number of bytes consumed.
pub fn parse(view : BytesView) -> (S2k, Int) raise {
  guard view.length() >= 2 else { @error.fail("s2k: truncated specifier") }
  let usage = view[0].to_int()
  if usage == 4 {
    guard view.length() >= 20 else {
      @error.fail("s2k: truncated Argon2 specifier")
    }
    let salt = view[1:17].to_owned()
    let passes = view[17].to_int()
    let parallelism = view[18].to_int()
    let memory_exp = view[19].to_int()
    validate_argon2(passes, parallelism, memory_exp)
    return (Argon2(salt, passes, parallelism, memory_exp), 20)
  }
  let hash_id = match @primitives.hash_id_of_number(view[1].to_int()) {
    Some(h) => h
    None => @error.fail("s2k: unknown hash algorithm \{view[1].to_int()}")
  }
  match usage {
    0 => (Simple(hash_id), 2)
    1 => {
      guard view.length() >= 10 else {
        @error.fail("s2k: truncated salted specifier")
      }
      (Salted(hash_id, view[2:10].to_owned()), 10)
    }
    3 => {
      guard view.length() >= 11 else {
        @error.fail("s2k: truncated iterated specifier")
      }
      (Iterated(hash_id, view[2:10].to_owned(), view[10].to_int()), 11)
    }
    _ => @error.fail("s2k: unsupported usage type \{usage}")
  }
}

///|
/// Validate the Argon2 parameters as RFC 9580 §3.7.1.4 requires: `t` and `p`
/// must be non-zero, the encoded memory size must be at most 31, and the
/// decoded memory `2^encoded_m` KiB must be at least `8*p`.
fn validate_argon2(
  passes : Int,
  parallelism : Int,
  memory_exp : Int,
) -> Unit raise {
  guard passes != 0 else {
    @error.fail("s2k: Argon2 passes t must be non-zero")
  }
  guard parallelism != 0 else {
    @error.fail("s2k: Argon2 parallelism p must be non-zero")
  }
  guard memory_exp >= 0 && memory_exp <= 31 else {
    @error.fail("s2k: Argon2 encoded memory \{memory_exp} is out of range")
  }
  guard memory_exp == 31 || 1 << memory_exp >= 8 * parallelism else {
    @error.fail(
      "s2k: Argon2 memory 2^\{memory_exp} KiB is below the 8*p minimum",
    )
  }
}

///|
/// The decoded Argon2 memory cost in KiB. Values at or above 2^31 (the
/// largest the wire can express) are clamped to just above the
/// implementation ceiling so `@primitives.argon2id` rejects them instead of
/// overflowing `Int`.
fn argon2_memory_kib(memory_exp : Int) -> Int {
  if memory_exp >= 31 {
    @primitives.ARGON2_MAX_MEMORY_KIB * 2
  } else {
    1 << memory_exp
  }
}

///|
/// Encode this specifier to its wire form.
pub fn S2k::encode(self : S2k) -> Bytes raise {
  match self {
    Simple(hash_id) => Bytes::from_array([0, hash_id.number().to_byte()])
    Salted(hash_id, salt) => {
      guard salt.length() == SALT_SIZE else {
        @error.fail("s2k: bad salt length")
      }
      let out : Array[Byte] = [1, hash_id.number().to_byte()]
      for b in salt {
        out.push(b)
      }
      Bytes::from_array(out)
    }
    Iterated(hash_id, salt, count_byte) => {
      guard salt.length() == SALT_SIZE else {
        @error.fail("s2k: bad salt length")
      }
      let out : Array[Byte] = [3, hash_id.number().to_byte()]
      for b in salt {
        out.push(b)
      }
      out.push(count_byte.to_byte())
      Bytes::from_array(out)
    }
    Argon2(salt, passes, parallelism, memory_exp) => {
      guard salt.length() == ARGON2_SALT_SIZE else {
        @error.fail("s2k: bad Argon2 salt length")
      }
      validate_argon2(passes, parallelism, memory_exp)
      let out : Array[Byte] = [4]
      for b in salt {
        out.push(b)
      }
      out.push(passes.to_byte())
      out.push(parallelism.to_byte())
      out.push(memory_exp.to_byte())
      Bytes::from_array(out)
    }
  }
}

///|
/// True for the Argon2 (type 4) specifier. RFC 9580 §3.7.2.1 permits it in
/// a Secret Key packet only with S2K usage octet 253 (AEAD).
pub fn S2k::is_argon2(self : S2k) -> Bool {
  match self {
    Argon2(_, _, _, _) => true
    _ => false
  }
}

///|
/// Decode an encoded count byte into the actual octet count
/// (RFC 9580 §3.7.1.3).
pub fn decode_count(count_byte : Int) -> Int {
  (16 + (count_byte & 15)) << ((count_byte >> 4) + 6)
}

///|
/// Pick the count byte that yields the smallest count >= `target`
/// (as GnuPG does). When no byte can reach the target, the largest count
/// (255) is returned: falling back to 0 would silently select the
/// *minimum* work factor instead of the maximum.
pub fn encode_count(target : Int) -> Int {
  for c in 0..<=255 {
    if decode_count(c) >= target {
      return c
    }
  }
  255
}

///|
/// The RFC 9580 §3.7.1 hash-based key derivation: output block `j` is
/// `H(zeros(j) || seed)`, concatenated and truncated to `key_len`. `seed`
/// already contains the salt (when there is one) followed by the
/// passphrase.
fn derive_hash_key(
  hash_id : @primitives.HashId,
  seed : BytesView,
  key_len : Int,
) -> Bytes {
  let out : Array[Byte] = Array(capacity=key_len)
  let mut j = 0
  while out.length() < key_len {
    let zeros = Bytes::make(j, b'\x00')
    let digest = hash_id.digest(@primitives.concat2(zeros, seed))
    for b in digest {
      if out.length() < key_len {
        out.push(b)
      }
    }
    j = j + 1
  }
  Bytes::from_array(out)
}

///|
/// Derive a key of `key_len` bytes from `passphrase` under this specifier,
/// enforcing `max_memory_kib` as an upper bound on the Argon2 memory cost.
/// A 20-octet specifier can ask for 2^31 KiB, so callers that parse
/// untrusted packets should pass a policy limit rather than rely on the
/// 2 GiB implementation ceiling that `derive_key` uses.
pub fn S2k::derive_key_capped(
  self : S2k,
  passphrase : BytesView,
  key_len : Int,
  max_memory_kib : Int,
) -> Bytes raise {
  match self {
    // Argon2 has no OpenPGP hash octet: the derivation is entirely different
    // from the hash-based forms, so it is a separate branch.
    Argon2(salt, passes, parallelism, memory_exp) => {
      guard salt.length() == ARGON2_SALT_SIZE else {
        @error.fail("s2k: bad Argon2 salt length")
      }
      // Re-validate: `S2k` is `pub(all)`, so a caller can build an
      // out-of-domain specifier directly.
      validate_argon2(passes, parallelism, memory_exp)
      @primitives.argon2id(
        passphrase,
        salt,
        passes,
        argon2_memory_kib(memory_exp),
        parallelism,
        key_len,
        max_memory_kib~,
      )
    }
    // RFC 9580 §3.7.1.1 (and RFC 4880 §3.7.1.1): the Simple specifier
    // hashes the passphrase itself — there is no salt. Passing an empty
    // seed here made every passphrase derive the same key, which silently
    // broke legacy (cipher-id usage octet) secret keys and any Simple-S2K
    // message.
    Simple(hash_id) => derive_hash_key(hash_id, passphrase, key_len)
    Salted(hash_id, salt) => {
      guard salt.length() == SALT_SIZE else {
        @error.fail("s2k: bad salt length")
      }
      // RFC 9580 §3.7.1.2: the hash input is the salt FOLLOWED BY the
      // passphrase (the old passphrase||salt order was a latent interop
      // bug, caught in the 2026-10-08 P2 research review).
      derive_hash_key(hash_id, @primitives.concat2(salt, passphrase), key_len)
    }
    Iterated(hash_id, salt, count_byte) => {
      guard salt.length() == SALT_SIZE else {
        @error.fail("s2k: bad salt length")
      }
      let mut count = decode_count(count_byte)
      // Salt length is guarded above, so combined is never empty here.
      let combined = salt.add(passphrase.to_owned())
      // RFC 9580 §3.7.1.3: at least one full salt‖passphrase copy is
      // hashed "regardless of the octet count", so a passphrase longer
      // than `count - 8` must not be truncated away.
      if count < combined.length() {
        count = combined.length()
      }
      // Repeat salt‖passphrase until `count` octets, then truncate.
      let data : Array[Byte] = Array(capacity=count)
      while data.length() < count {
        for b in combined {
          data.push(b)
        }
      }
      derive_hash_key(hash_id, Bytes::from_array(data[0:count]), key_len)
    }
  }
}

///|
/// Derive a key of `key_len` bytes from `passphrase` under this specifier,
/// capped at the implementation's 2 GiB Argon2 ceiling
/// (`@primitives.ARGON2_MAX_MEMORY_KIB`). Use `derive_key_capped` when
/// parsing untrusted specifiers and a tighter policy is wanted.
pub fn S2k::derive_key(
  self : S2k,
  passphrase : BytesView,
  key_len : Int,
) -> Bytes raise {
  self.derive_key_capped(passphrase, key_len, @primitives.ARGON2_MAX_MEMORY_KIB)
}

///|
pub extend S2k with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend S2k with Eq::{not_equal, equal}
