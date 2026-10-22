///|
/// Symmetric block cipher abstraction. OpenPGP modes (CFB variants, AEAD)
/// only need single-block encrypt/decrypt with a fixed key, so this is all
/// the rest of the module is allowed to know about the primitive.
///
/// Block size is always 16 for every algorithm OpenPGP 0/1 modes use with
/// AES; still, callers must consult `block_size` rather than assume.
pub(open) trait BlockCipher {
  fn block_size(Self) -> Int32
  fn encrypt_block(Self, BytesView) -> Bytes
  fn decrypt_block(Self, BytesView) -> Bytes

  /// Best-effort scrub of expanded key material (GC languages cannot
  /// guarantee it; see project README).
  fn wipe(Self) -> Unit
}

///|
/// Symmetric cipher algorithms, RFC 9580 §9.3 numbers. TripleDES (2) and
/// CAST5 (3) exist for the read side only — RFC 4880 §9.2 makes 3DES a
/// MUST-implement and CAST5 was GnuPG's pre-AES default; the generation
/// paths always pick AES.
pub(all) enum CipherAlgo {
  Tripledes
  Cast5
  Aes128
  Aes192
  Aes256
} derive(Eq, Debug)

///|
pub fn CipherAlgo::number(self : CipherAlgo) -> Int32 {
  match self {
    Tripledes => 2
    Cast5 => 3
    Aes128 => 7
    Aes192 => 8
    Aes256 => 9
  }
}

///|
pub fn cipher_algo_of_number(n : Int32) -> CipherAlgo? {
  match n {
    2 => Some(Tripledes)
    3 => Some(Cast5)
    7 => Some(Aes128)
    8 => Some(Aes192)
    9 => Some(Aes256)
    _ => None
  }
}

///|
pub fn CipherAlgo::key_size(self : CipherAlgo) -> Int32 {
  match self {
    Tripledes => 24
    Cast5 => 16
    Aes128 => 16
    Aes192 => 24
    Aes256 => 32
  }
}

///|
/// Block size used by every supported algorithm.
pub const BLOCK_SIZE : Int32 = 16

///|
/// Display name of a symmetric cipher algorithm, for error messages.
fn cipher_algo_name(algo : CipherAlgo) -> String {
  match algo {
    Tripledes => "TripleDES"
    Cast5 => "CAST5"
    Aes128 => "AES-128"
    Aes192 => "AES-192"
    Aes256 => "AES-256"
  }
}

///|
/// Construct the block cipher for `algo` under `key`.
pub fn new_block_cipher(
  algo : CipherAlgo,
  key : BytesView,
) -> &BlockCipher raise {
  guard key.length() == algo.key_size() else {
    @error.fail(
      "key length \{key.length()} does not match \{cipher_algo_name(algo)} key size \{algo.key_size()}",
    )
  }
  match algo {
    Tripledes => new_des_ede3(key)
    Cast5 => new_cast5(key)
    _ => new_aes(key)
  }
}

///|
pub extend CipherAlgo with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend CipherAlgo with Eq::{not_equal, equal}
