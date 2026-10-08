///|
/// GnuPG 2.4.5, v3 PKESK to the RSA key in `interop_our_key.asc`, with a
/// non-default symmetric algorithm:
///
///   gpg --batch --trust-model always --encrypt --armor \
///     --recipient 5DC1E21718EB2F136E08D97CC43F37EE4526820A \
///     --cipher-algo AES128 \
///     < "secret for moonbit rsa aes128" \
///     > testdata/interop_gpg_rsa_aes128_message.asc
///
/// A v1 SEIPD packet names no cipher of its own: the only cipher octet
/// travels inside the PKCS#1 payload (RFC 9580 §5.1.3). A reader that
/// assumes AES-256 therefore loses every message GnuPG encrypted with
/// anything else, even though the session key itself decrypts fine.

///|
test "decrypt a GnuPG AES-128 v3 PKESK message to our RSA key" {
  let key = @api.PrivateKey::from_armored(
    @fs.read_file_to_string("testdata/interop_our_key.asc"),
  )
  let data = @api.decrypt_with_private_key(
    @fs.read_file_to_string("testdata/interop_gpg_rsa_aes128_message.asc"),
    key,
  )
  assert_eq(data, @primitives.utf8_bytes("secret for moonbit rsa aes128\n"))
}
