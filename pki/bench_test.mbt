///|
test "bench 2048 keygen" {
  let key = @pki.generate_rsa_key(bits=2048)
  assert_true(key.public.n.bit_length() == 2048)
  ignore(key)
}
