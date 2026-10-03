///|
/// Hash algorithms used by OpenPGP, identified by their RFC 9580 §9.5
/// algorithm numbers. This is the PGP-level identity; concrete digest
/// computation is delegated to `moonbitlang/x/crypto` inside this package
/// only, so the hash backend can be swapped without touching callers.
pub(all) enum HashId {
  Md5
  Sha1
  Ripemd160
  Sha224
  Sha256
  Sha384
  Sha512
} derive(Eq, Debug)

///|
pub fn HashId::number(self : HashId) -> Int {
  match self {
    Md5 => 1
    Sha1 => 2
    Ripemd160 => 3
    Sha224 => 11
    Sha256 => 8
    Sha384 => 9
    Sha512 => 10
  }
}

///|
pub fn hash_id_of_number(n : Int) -> HashId? {
  match n {
    1 => Some(Md5)
    2 => Some(Sha1)
    3 => Some(Ripemd160)
    8 => Some(Sha256)
    9 => Some(Sha384)
    10 => Some(Sha512)
    11 => Some(Sha224)
    _ => None
  }
}

///|
/// Size of the digest output in bytes.
pub fn HashId::digest_size(self : HashId) -> Int {
  match self {
    Md5 => 16
    Sha1 => 20
    Ripemd160 => 20
    Sha224 => 28
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
/// Digest function block size in bytes (as used by HMAC, RFC 2104).
pub fn HashId::block_size(self : HashId) -> Int {
  match self {
    Sha384 | Sha512 => 128
    _ => 64
  }
}

///|
/// Digest a single buffer.
pub fn HashId::digest(self : HashId, data : BytesView) -> Bytes {
  match self {
    Md5 => Bytes::from_iter(@xcrypto.md5(data).iter())
    Sha1 => Bytes::from_iter(@xcrypto.sha1(data).iter())
    Ripemd160 => Bytes::from_iter(@xcrypto.ripemd160(data).iter())
    Sha224 => Bytes::from_iter(@xcrypto.sha224(data).iter())
    Sha256 => Bytes::from_iter(@xcrypto.sha256(data).iter())
    Sha384 => Bytes::from_iter(@xcrypto.sha384(data).iter())
    Sha512 => Bytes::from_iter(@xcrypto.sha512(data).iter())
  }
}

///|
/// HMAC (RFC 2104) over a single buffer, using this hash algorithm.
pub fn HashId::hmac(self : HashId, key : BytesView, data : BytesView) -> Bytes {
  let bs = self.block_size()
  let k : Bytes = if key.length() > bs {
    self.digest(key)
  } else {
    key.to_owned()
  }
  let kp = pad_right(k, bs)
  let ipad = Bytes::makei(bs, i => kp[i] ^ b'\x36')
  let opad = Bytes::makei(bs, i => kp[i] ^ b'\x5c')
  let inner = self.digest(ipad.add(data.to_owned()))
  self.digest(opad.add(inner))
}

///|
/// DER DigestInfo prefix for this hash (PKCS#1 v1.5 signatures).
pub fn HashId::der_prefix(self : HashId) -> Bytes {
  from_hex_unchecked(
    match self {
      Md5 => "3020300c06082a864886f70d020505000410"
      Sha1 => "3021300906052b0e03021a05000414"
      Ripemd160 => "3021300906052b2403020105000414"
      Sha224 => "302d300d06096086480165030402040500041c"
      Sha256 => "3031300d060960864801650304020105000420"
      Sha384 => "3041300d060960864801650304020205000430"
      Sha512 => "3051300d060960864801650304020305000440"
    },
  )
}

///|
/// Hex decode of a compile-time constant; invalid constants abort.
fn from_hex_unchecked(s : String) -> Bytes {
  match hex_decode_const(s) {
    Some(b) => b
    None => abort("primitives: invalid constant hex string")
  }
}

///|
fn hex_decode_const(s : String) -> Bytes? {
  Some(@hex.decode(s) catch { _ => return None })
}

///|
pub extend HashId with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend HashId with Eq::{not_equal, equal}
