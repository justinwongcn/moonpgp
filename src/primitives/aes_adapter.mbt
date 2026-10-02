///|
/// AES adapter on `moonbitlang/x/crypto`'s AES-ECB primitives (official
/// dependency). x/crypto exposes a stateless ECB API — each call derives
/// the key schedule afresh — so the adapter holds only the raw key and
/// delegates one block at a time, which is exactly how the OpenPGP-CFB
/// loops consume the primitive. The per-call schedule re-derivation makes
/// the AES path a few times slower than a cached-schedule cipher; accepted
/// here to keep the whole symmetric path on officially maintained code.
priv struct AesAdapter {
  mut key : Bytes
}

///|
impl BlockCipher for AesAdapter with fn block_size(_self) -> Int {
  BLOCK_SIZE
}

///|
impl BlockCipher for AesAdapter with fn encrypt_block(self, block) -> Bytes {
  // Unreachable error path: key length is validated at construction and
  // callers always pass exactly one 16-octet block.
  @xcrypto.aes_ecb_encrypt(self.key.exact_view(), block) catch {
    _ => abort("aes: encrypt_block failed")
  }
}

///|
impl BlockCipher for AesAdapter with fn decrypt_block(self, block) -> Bytes {
  // Unreachable error path: same invariants as encrypt_block.
  @xcrypto.aes_ecb_decrypt(self.key.exact_view(), block) catch {
    _ => abort("aes: decrypt_block failed")
  }
}

///|
/// Best-effort scrub of the key copy (GC languages cannot guarantee it;
/// see project README). x/crypto keeps no schedule between calls, so the
/// key copy is all the long-lived secret there is.
impl BlockCipher for AesAdapter with fn wipe(self) -> Unit {
  self.key = Bytes::make(self.key.length(), b'\x00')
}

///|
/// Trait-object constructor used by every OpenPGP mode. x/crypto would
/// raise `CryptoError` on every call for a bad key length; reject it up
/// front instead.
pub fn new_aes(key : BytesView) -> &BlockCipher raise {
  guard key.length() == 16 || key.length() == 24 || key.length() == 32 else {
    @error.fail("AES init failed")
  }
  AesAdapter::{ key: key.to_owned(), }
}
