// Hacker round 2 (2026-11-13 morning), composition facet (agent E1):
// the F17 export gate checked is_locked() — "any component locked" — so
// a mixed certificate (plaintext primary, locked subkey) passed the gate
// and exported the primary's plaintext secret material by default.

///|
test "mixed-lock certificate refuses default export (E1)" {
  // RSA generate_key: primary + encryption subkey — the mixed state
  // needs two components. 3072-bit keygen keeps this test ~10 s.
  let k = generate_key("Mixed <mixed@example.net>")
  let locked = k.lock("passphrase-1")
  // Splice a transferable: plaintext primary (from k) + locked subkey
  // (from locked), everything else from the plaintext key.
  let plain = @packet.parse_packets(
    k.to_bytes(allow_unlocked=true).exact_view(),
  )
  let lockd = @packet.parse_packets(locked.to_bytes().exact_view())
  // Secret components ride tags SecretKey (primary) and SecretSubkey.
  let lockd_sk : Array[Bytes] = []
  for p in lockd {
    if p.tag() == @packet.SecretKey || p.tag() == @packet.SecretSubkey {
      lockd_sk.push(p.body())
    }
  }
  assert_eq(lockd_sk.length(), 2)
  let mixed : Array[Byte] = []
  let mut seen = 0
  for p in plain {
    let body = if p.tag() == @packet.SecretKey ||
      p.tag() == @packet.SecretSubkey {
      seen = seen + 1
      if seen == 2 {
        lockd_sk[1]
      } else {
        p.body()
      }
    } else {
      p.body()
    }
    for b in @packet.serialize_packet(p.tag(), body.exact_view()).exact_view() {
      mixed.push(b)
    }
  }
  let re = PrivateKey::from_bytes(Bytes::from_array(mixed).exact_view())
  // The mixed certificate reports locked (any-component semantics), but
  // the primary's material is plaintext on the wire.
  assert_true(re.is_locked())
  // The gate must refuse: exporting writes the primary's plaintext
  // material by default.
  let raised = try {
    ignore(re.to_armored())
    false
  } catch {
    _ => true
  }
  assert_true(raised)
  // Explicit opt-in still exports (the caller accepted the plaintext).
  assert_true(re.to_armored(allow_unlocked=true).has_prefix("-----BEGIN PGP"))
}

///|
/// Cleanup round (E5): a CRLF line-ending variant of a clearsigned
/// message (Windows gpg, SMTP-stored mail) must verify like the LF
/// original. The digest canonicalization already normalizes line
/// endings; the header-section parser was the hard failure — the "\r"
/// terminator line failed the empty-line check and raised "illegal
/// armor header".
test "verify_cleartext accepts CRLF line endings (E5)" {
  let k = generate_ed25519_key("CRLF <crlf@example.net>")
  let text = "line one\nline two\n- dash here\n"
  let ct = sign_cleartext(text, k)
  let (lf_text, lf_status) = verify_cleartext(ct, k.to_public())
  assert_true(lf_status is Ok)
  let crlf = ct.replace_all(old="\n", new="\r\n")
  let (crlf_text, crlf_status) = verify_cleartext(crlf, k.to_public())
  assert_true(crlf_status is Ok)
  assert_eq(crlf_text, lf_text)
}
