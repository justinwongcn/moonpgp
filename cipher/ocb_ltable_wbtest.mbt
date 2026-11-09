///|
/// C4: the OCB key-dependent L table must stay logarithmic. One entry per
/// message block made a 1 GiB tag-20 message allocate ~6.7e7 `Bytes`
/// objects — GBs of pure waste before any length gate — while every lookup
/// goes through `l[ocb_ntz(i)]` and never needs more than 28 entries for
/// Int32-sized messages.
test "ocb l-table is capped regardless of block count" {
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    Bytes::make(32, 0x11).exact_view(),
  )
  let (_, _, large) = ocb_l_table(bc, 67108864)
  assert_true(large.length() <= 32)
  // Small messages still get exactly the entries their indices need.
  let (_, _, small) = ocb_l_table(bc, 5)
  assert_eq(small.length(), 6)
  // A real round trip through the capped table stays byte-exact: a 2 KiB
  // payload plus AD walks ntz indices up to 7 with the AD/payload loops.
  let nonce = Bytes::make(15, 0x22)
  let ad = Bytes::make(48, 0x33)
  let plain = Bytes::make(2048, 0x44)
  let ct = ocb_encrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    plain.exact_view(),
  )
  let back = ocb_decrypt(
    bc,
    nonce.exact_view(),
    ad.exact_view(),
    ct.exact_view(),
  )
  assert_eq(back, plain)
}
