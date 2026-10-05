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
} derive(Eq, Debug)

///|
/// Salt length in octets for salted/iterated S2K.
pub const SALT_SIZE : Int = 8

///|
/// Parse an S2K specifier from the front of `view`. Returns the specifier
/// and the number of bytes consumed.
pub fn parse(view : BytesView) -> (S2k, Int) raise {
  guard view.length() >= 2 else { @error.fail("s2k: truncated specifier") }
  let usage = view[0].to_int()
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
/// (as GnuPG does). Returns 0 when no byte can reach the target.
pub fn encode_count(target : Int) -> Int {
  for c in 0..<=255 {
    if decode_count(c) >= target {
      return c
    }
  }
  0
}

///|
/// Derive a key of `key_len` bytes from `passphrase` under this specifier.
pub fn S2k::derive_key(
  self : S2k,
  passphrase : BytesView,
  key_len : Int,
) -> Bytes raise {
  let hash_id : @primitives.HashId = match self {
    Simple(h) => h
    Salted(h, _) => h
    Iterated(h, _, _) => h
  }
  let seed : Bytes = match self {
    Simple(_) => Bytes::new(0)
    Salted(_, salt) => {
      guard salt.length() == SALT_SIZE else {
        @error.fail("s2k: bad salt length")
      }
      @primitives.concat2(passphrase, salt)
    }
    Iterated(_, salt, count_byte) => {
      guard salt.length() == SALT_SIZE else {
        @error.fail("s2k: bad salt length")
      }
      let count = decode_count(count_byte)
      // Salt length is guarded above, so combined is never empty here.
      let combined = salt.add(passphrase.to_owned())
      // Repeat salt||passphrase until `count` octets, then truncate.
      let data : Array[Byte] = Array(capacity=count)
      while data.length() < count {
        for b in combined {
          data.push(b)
        }
      }
      Bytes::from_array(data[0:count])
    }
  }
  let out : Array[Byte] = Array(capacity=key_len)
  let mut j = 0
  while out.length() < key_len {
    // Each output block hashes j zero octets followed by the seed.
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
pub extend S2k with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend S2k with Eq::{not_equal, equal}
