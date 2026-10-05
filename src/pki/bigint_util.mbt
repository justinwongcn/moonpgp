///|
/// Extended Euclid: returns (g, x) with a*x + m*y = g = gcd(a, m) and
/// 0 <= x < m when gcd = 1.
fn ext_gcd(a : BigInt, m : BigInt) -> (BigInt, BigInt) {
  let mut old_r = a
  let mut r = m
  let mut old_s = BigInt::from_int(1)
  let mut s = BigInt::from_int(0)
  while !r.is_zero() {
    let q = old_r.div(r)
    let tmp_r = old_r.sub(q.mul(r))
    old_r = r
    r = tmp_r
    let tmp_s = old_s.sub(q.mul(s))
    old_s = s
    s = tmp_s
  }
  // Normalize the coefficient into [0, m).
  let x = old_s.mod(m)
  (old_r, if x < BigInt::from_int(0) { x.add(m) } else { x })
}

///|
/// Modular inverse via the extended Euclidean algorithm. Raises when `a`
/// is not invertible modulo `m`.
pub fn mod_inverse(a : BigInt, m : BigInt) -> BigInt raise {
  let (g, x) = ext_gcd(a.mod(m), m)
  guard g.equal_int(1) else {
    @error.fail("pki: modular inverse does not exist")
  }
  x
}

///|
/// Uniformly random BigInt in [0, 2^bits).
fn random_bigint(bits : Int) -> BigInt raise {
  let nbytes = (bits + 7) / 8
  let raw = @primitives.random_bytes(nbytes)
  let mut v = BigInt::from_octets(raw.exact_view(), signum=1)
  let excess = nbytes * 8 - bits
  if excess > 0 {
    v = v.shr(excess)
  }
  v
}

///|
/// Uniformly random BigInt in [low, high).
fn random_range(low : BigInt, high : BigInt) -> BigInt raise {
  let span = high.sub(low)
  let bits = span.bit_length()
  while true {
    let v = random_bigint(bits)
    if v < span {
      return low.add(v)
    }
  } nobreak {
    // Unreachable: the only exit is the return above; the nobreak arm
    // satisfies the typechecker (E4108 — `while true` is not diverging).
    abort("unreachable")
  }
}

///|
/// Small primes for trial division (first odd primes below 2000). Cost of
/// rebuilding is negligible next to the Miller-Rabin rounds it filters.
fn small_primes() -> Array[BigInt] {
  [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163,
    167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
    449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
    563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
    653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757,
    761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
    991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171,
    1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
    1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367,
    1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459,
    1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553,
    1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627,
    1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861,
    1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951,
    1973, 1979, 1987, 1993, 1997, 1999,
  ].map(n => BigInt::from_int(n))
}

///|
/// Miller-Rabin primality witness test for odd `n` with base `a`.
fn is_witness(a : BigInt, n : BigInt) -> Bool {
  // n odd, n-1 = d * 2^s
  let one = BigInt::from_int(1)
  let mut d = n.sub(one)
  let mut s = 0
  while d.mod(BigInt::from_int(2)).equal_int(0) {
    d = d.shr(1)
    s = s + 1
  }
  let mut x = a.pow(d, modulus=n)
  if x.equal_int(1) || x.equal(n.sub(one)) {
    return false
  }
  for _ in 0..<(s - 1) {
    x = x.mul(x).mod(n)
    if x.equal(n.sub(one)) {
      return false
    }
  }
  true
}

///|
/// Miller-Rabin probabilistic primality test with `rounds` random bases
/// (plus trial division). Error probability < 4^-rounds.
pub fn is_probable_prime(n : BigInt, rounds~ : Int) -> Bool raise {
  if n.compare_int(2) < 0 {
    return false
  }
  if n.equal_int(2) || n.equal_int(3) {
    return true
  }
  if n.mod(BigInt::from_int(2)).equal_int(0) {
    return false
  }
  for p in small_primes() {
    if n.equal(p) {
      return true
    }
    if n.mod(p).equal_int(0) {
      return false
    }
  }
  let two = BigInt::from_int(2)
  let n_minus_1 = n.sub(BigInt::from_int(1))
  for _ in 0..<rounds {
    let a = random_range(two, n_minus_1)
    if is_witness(a, n) {
      return false
    }
  }
  true
}

///|
/// Generate a random probable prime with exactly `bits` bits whose
/// minus-one has no factor in common with `coprime` (used for p-1
/// coprime to the public exponent).
pub fn random_prime(
  bits : Int,
  coprime~ : BigInt,
  rounds~ : Int,
) -> BigInt raise {
  guard bits >= 2 else { @error.fail("pki: prime bit size too small") }
  let e = BigInt::from_int(0).lor(coprime)
  // Loop-invariant thresholds for the "top two bits set" requirement.
  let top = BigInt::from_int(1).shl(bits - 1)
  let second = BigInt::from_int(1).shl(bits - 2)
  while true {
    // Top two bits set so n*p has full size; force odd.
    let mut candidate = random_bigint(bits)
    candidate = candidate.lor(top).lor(second)
    if candidate.mod(BigInt::from_int(2)).equal_int(0) {
      candidate = candidate.sub(BigInt::from_int(1))
    }
    if candidate.bit_length() != bits {
      continue
    }
    if !is_probable_prime(candidate, rounds~) {
      continue
    }
    // gcd(p-1, e) == 1
    let pm1 = candidate.sub(BigInt::from_int(1))
    let g = ext_gcd(e, pm1).0
    if g.equal_int(1) {
      return candidate
    }
  } nobreak {
    // Unreachable: the only exit is the return above; the nobreak arm
    // satisfies the typechecker (E4108 — `while true` is not diverging).
    abort("unreachable")
  }
}
