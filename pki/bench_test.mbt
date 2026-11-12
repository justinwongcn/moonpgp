///|

///|
test "bench 3072 keygen" {
  let start = @primitives.unix_now()
  let key = @pki.generate_rsa_key(bits=3072)
  let elapsed = @primitives.unix_now() - start
  assert_true(key.public.n.bit_length() == 3072)
  println("BENCH-3072-KEYGEN-SECS: \{elapsed}")
}
