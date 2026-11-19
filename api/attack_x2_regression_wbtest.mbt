///|
/// X2 conformance regression probes (audit-conformance-20261119): pins the
/// FIXED behavior of the freshly landed gates — v4 recipient prefs picking
/// (c2g3), SKESK msg-algo parameterization + CAST5/3DES zero-IV unwrap
/// (c1g2), v6 SKESK weak S2K hash refusal (c2g1), OPS<->signature pairing
/// rows (c1g6), usage-0 secret checksum gates (c2g5), weak-hash
/// issuance/validation cutoffs (c2g2/c2g7/c1g3). The bypass/leniency
/// probes live in attack_x2_hits_wbtest.mbt.
let x2_payload : Bytes = Bytes::from_array([
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
])

///|
fn x2_raises(f : () -> Unit raise) -> Bool {
  try {
    f()
    false
  } catch {
    _ => true
  }
}

///|
fn x2_literal_wire() -> Bytes raise {
  @packet.serialize_packet(
    @packet.Literal,
    @packet.LiteralPacket::binary(x2_payload.exact_view(), file_name="x.txt")
    .to_body()
    .exact_view(),
  )
}

///|
/// A v4 recipient (private + prefs-crafted public half) with a crafted
/// Preferred Symmetric Algorithms body. The generated key's own self-sig
/// already carries prefs [9,8,7]; the crafted bodies are prepended and the
/// original prefs subpackets stripped, so `pref_bodies` fully controls the
/// list find_subpacket sees.
fn x2_recipient_with_prefs(
  user_id : String,
  pref_bodies : Array[Bytes],
) -> (PrivateKey, PublicKey) raise {
  let key = generate_ed25519_key(user_id)
  let subs : Array[@packet.SigSubpacket] = pref_bodies.map(body => {
    (
      { critical: false, sub_type: @packet.SIGSUB_PREFERRED_SYM_ALGOS, body, } :
      @packet.SigSubpacket)
  })
  let sig = key.user_ids[0].self_signature
  let stripped = sig
    .hashed_subpackets()
    .filter(sp => sp.sub_type != @packet.SIGSUB_PREFERRED_SYM_ALGOS)
  let modified = {
    ..sig,
    hashed_subpackets: {
      let all : Array[@packet.SigSubpacket] = []
      for sp in subs {
        all.push(sp)
      }
      for sp in stripped {
        all.push(sp)
      }
      all
    },
  }
  let pk : PublicKey = {
    ..key.to_public(),
    user_ids: [{ user_id, self_signature: modified, revocation: None, }],
  }
  (key, pk)
}

///|
fn x2_first_skesk(message : String) -> @packet.SkeskPacket raise {
  let block = @armor.decode(message)
  for p in @packet.parse_packets(@armor.ArmorBlock::data(block).exact_view()) {
    if p.tag() == @packet.Skesk {
      return @packet.SkeskPacket::parse(p.body().exact_view())
    }
  }
  @error.fail("x2: no SKESK in message")
}

///|
/// P3a + P4a (c2g3 / build_skesk parameterization): recipients with prefs
/// [9,8,7] and [7] share exactly AES-128 — the message cipher must move to
/// AES-128, and the SKESK must wrap [AES-128 || 16-octet key] so the
/// password path still opens it (read side identifies the message cipher
/// by wrapped[0], RFC 9580 §5.3.1).
test "x2 P3a: prefs intersection picks AES-128 and roundtrips" {
  let (key1, r1) = x2_recipient_with_prefs("R1 <r1@example.com>", [
    Bytes::from_array([9, 8, 7]),
  ])
  let (_key2, r2) = x2_recipient_with_prefs("R2 <r2@example.com>", [
    Bytes::from_array([7]),
  ])
  let msg = seal_esks_and_seipd(
    x2_literal_wire().exact_view(),
    [r1, r2],
    ["hunter2"],
    [],
  )
  // The SKESK's wrapped value must name AES-128 (7) as the message cipher
  // and carry a 16-octet session key (AES-128 key size).
  let skesk = x2_first_skesk(msg)
  let (algo, key, _ver, _proven) = unwrap_one_skesk(
    skesk,
    "hunter2",
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 7)
  assert_eq(key.length(), 16)
  // Full password-path roundtrip over the AES-128 SEIPD v1.
  let data = decrypt_with_password(msg, "hunter2")
  assert_eq(data, x2_payload)
  // And the key path too.
  let block = @armor.decode(msg)
  let plain = decrypt_binary_with_private_key(
    @armor.ArmorBlock::data(block).exact_view(),
    key1,
  )
  assert_eq(plain, x2_payload)
}

///|
/// P3b (过严 probe): a recipient whose preference list is explicitly empty.
/// RFC 9580 §5.2.3.7 defines an empty list; §12.2 then allows no cipher at
/// all — the seal raises rather than violating the (empty) constraint.
test "x2 P3b: empty prefs body makes the seal fail" {
  let (_k, r) = x2_recipient_with_prefs("E <e@example.com>", [Bytes::new(0)])
  assert_true(
    x2_raises(() => {
      ignore(seal_esks_and_seipd(x2_literal_wire().exact_view(), [r], [], []))
    }),
  )
}

///|
/// P3c: duplicate prefs subpackets in one certification. find_subpacket
/// takes the FIRST — the pair ([7], [9,8,7]) must pick AES-128, not the
/// broader later list.
test "x2 P3c: duplicate prefs subpacket — first body wins" {
  let (_k, r) = x2_recipient_with_prefs("D <d@example.com>", [
    Bytes::from_array([7]),
    Bytes::from_array([9, 8, 7]),
  ])
  let msg = seal_esks_and_seipd(x2_literal_wire().exact_view(), [r], ["pw"], [])
  let (algo, key, _v, _p) = unwrap_one_skesk(
    x2_first_skesk(msg),
    "pw",
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 7)
  assert_eq(key.length(), 16)
}

///|
/// P3d: two User IDs, the second carrying prefs [7]. The picker iterates
/// the User IDs in wire order and keeps the LAST certification's list —
/// "the latest certification carrying the subpacket" per the docstring.
test "x2 P3d: second user id's prefs override the first" {
  let key = generate_ed25519_key("U <u@example.com>")
  let sig = key.user_ids[0].self_signature
  let prefs : @packet.SigSubpacket = {
    critical: false,
    sub_type: @packet.SIGSUB_PREFERRED_SYM_ALGOS,
    body: Bytes::from_array([7]),
  }
  let modified = {
    ..sig,
    hashed_subpackets: [prefs, ..sig.hashed_subpackets()],
  }
  let pk : PublicKey = {
    ..key.to_public(),
    user_ids: [
      key.user_ids[0],
      {
        user_id: "U2 <u2@example.com>",
        self_signature: modified,
        revocation: None,
      },
    ],
  }
  let msg = seal_esks_and_seipd(x2_literal_wire().exact_view(), [pk], ["pw"], [])
  let (algo, _key, _v, _p) = unwrap_one_skesk(
    x2_first_skesk(msg),
    "pw",
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 7)
}

///|
/// P3e (过严 probe): the only common preference is CAST5 (3). RFC 9580
/// §12.2 would allow it; the picker's candidate list is AES-only so the
/// seal fails instead. Security-tightening tradeoff — recorded, not a bug.
test "x2 P3e: CAST5-only common prefs fail the seal" {
  let (_k1, r1) = x2_recipient_with_prefs("C1 <c1@example.com>", [
    Bytes::from_array([3]),
  ])
  let (_k2, r2) = x2_recipient_with_prefs("C2 <c2@example.com>", [
    Bytes::from_array([3]),
  ])
  assert_true(
    x2_raises(() => {
      ignore(
        seal_esks_and_seipd(x2_literal_wire().exact_view(), [r1, r2], [], []),
      )
    }),
  )
}

///|
/// P3f: an unconstrained recipient (no prefs subpacket at all) does not
/// block the constrained one's choice.
test "x2 P3f: unconstrained recipient ignores intersection" {
  let (_k1, r1) = x2_recipient_with_prefs("A <a@example.com>", [])
  let (_k2, r2) = x2_recipient_with_prefs("B <b@example.com>", [
    Bytes::from_array([7]),
  ])
  let msg = seal_esks_and_seipd(
    x2_literal_wire().exact_view(),
    [r1, r2],
    ["pw"],
    [],
  )
  let (algo, _key, _v, _p) = unwrap_one_skesk(
    x2_first_skesk(msg),
    "pw",
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 7)
}

///|
/// P4b (c1g2 read-side, attacker-crafted legacy shape): a v4 SKESK whose
/// wrapping cipher is CAST5 — 8-octet block, so the zero IV is 8 octets.
/// Before the fix the reader hardcoded a 16-octet IV and every such
/// message misclassified as a wrong passphrase. The wrapped value names
/// AES-256 as the message cipher, checksum-free shape.
test "x2 P4b: CAST5-wrapped v4 SKESK unwraps" {
  let passphrase = "legacy"
  let session_key = Bytes::make(32, 0x42)
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    Bytes::make(8, 0x11),
    @s2k.encode_count(1024),
  )
  let wrapping_key = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    16,
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Cast5,
    wrapping_key.exact_view(),
  )
  let plain = Bytes::from_array([9]).add(session_key)
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(bc.block_size(), b'\x00').exact_view(),
    plain.exact_view(),
  )
  let skesk : @packet.SkeskPacket = {
    version: 4,
    cipher_algo: 3,
    aead_algo: 0,
    s2k,
    iv: Bytes::new(0),
    encrypted_session_key: esk,
  }
  let (algo, key, _v, proven) = unwrap_one_skesk(
    skesk,
    passphrase,
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 9)
  assert_eq(key, session_key)
  // Checksum-free shape: the passphrase is only proven at the payload check.
  assert_false(proven)
}

///|
/// P4c (c1g2 read-side): the 3DES twin — 24-octet key, 8-octet block.
test "x2 P4c: 3DES-wrapped v4 SKESK unwraps" {
  let passphrase = "tripple"
  let session_key = Bytes::make(32, 0x43)
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha256,
    Bytes::make(8, 0x22),
    @s2k.encode_count(1024),
  )
  let wrapping_key = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    24,
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Tripledes,
    wrapping_key.exact_view(),
  )
  let plain = Bytes::from_array([9]).add(session_key)
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(bc.block_size(), b'\x00').exact_view(),
    plain.exact_view(),
  )
  let skesk : @packet.SkeskPacket = {
    version: 4,
    cipher_algo: 2,
    aead_algo: 0,
    s2k,
    iv: Bytes::new(0),
    encrypted_session_key: esk,
  }
  let (algo, key, _v, _proven) = unwrap_one_skesk(
    skesk,
    passphrase,
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 9)
  assert_eq(key, session_key)
}

///|
/// P4d (c2g1): a v6 SKESK with an SHA-1 S2K hash must be refused before
/// any derivation — no passphrase opens it, and the error is malformed,
/// not a wrong-passphrase retry bait.
test "x2 P4d: v6 SKESK with SHA-1 S2K refuses" {
  let skesk : @packet.SkeskPacket = {
    version: 6,
    cipher_algo: 9,
    aead_algo: 2,
    s2k: @s2k.Iterated(
      @primitives.Sha1,
      Bytes::make(8, 0x33),
      @s2k.encode_count(1024),
    ),
    iv: Bytes::make(15, 0x00),
    encrypted_session_key: Bytes::make(48, 0x00),
  }
  assert_true(
    x2_raises(() => {
      ignore(
        unwrap_one_skesk(
          skesk,
          "anything",
          @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
          budget=S2KBudget::new(),
        ),
      )
    }),
  )
}

///|
/// P4e: the v4 twin stays allowed — SHA-1 S2K on a v4 SKESK is legacy
/// input the reader must still accept (the §9.5 gate is v6-only by text).
test "x2 P4e: v4 SKESK with SHA-1 S2K still unwraps (legacy)" {
  let passphrase = "old"
  let session_key = Bytes::make(32, 0x44)
  let s2k : @s2k.S2k = @s2k.Iterated(
    @primitives.Sha1,
    Bytes::make(8, 0x44),
    @s2k.encode_count(1024),
  )
  let wrapping_key = s2k.derive_key(
    @primitives.utf8_bytes(passphrase).exact_view(),
    32,
  )
  let bc = @primitives.new_block_cipher(
    @primitives.Aes256,
    wrapping_key.exact_view(),
  )
  let plain = Bytes::from_array([9]).add(session_key)
  let esk = @cipher.cfb_encrypt(
    bc,
    Bytes::make(16, b'\x00').exact_view(),
    plain.exact_view(),
  )
  let skesk : @packet.SkeskPacket = {
    version: 4,
    cipher_algo: 9,
    aead_algo: 0,
    s2k,
    iv: Bytes::new(0),
    encrypted_session_key: esk,
  }
  let (algo, key, _v, _proven) = unwrap_one_skesk(
    skesk,
    passphrase,
    @primitives.DEFAULT_ARGON2_MAX_MEMORY_KIB,
    budget=S2KBudget::new(),
  )
  assert_eq(algo.number(), 9)
  assert_eq(key, session_key)
}

///|
/// P5a (c1g6 control): the legit pairing — OPS v3 + v4 signature, same
/// key, same type, same hash, same pub-algo — must still verify Ok.
test "x2 P5a: sign_inline roundtrip verifies (OPS v3 + v4 sig)" {
  let key = generate_ed25519_key("S <s@example.com>")
  let msg = sign_inline(x2_payload.exact_view(), key)
  let (data, status) = verify_inline(msg, key.to_public())
  assert_eq(data, x2_payload)
  assert_eq(status, VerifyStatus::Ok)
}

///|
fn x2_inline_stream(
  ops : @packet.OnePassSigPacket,
  sig : @packet.SignaturePacket,
) -> String raise {
  let w = @packet.Writer::new()
  w.bytes(
    @packet.serialize_packet(@packet.OnePassSig, ops.to_body().exact_view()).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(
      @packet.Literal,
      @packet.LiteralPacket::binary(x2_payload.exact_view(), file_name="x.txt")
      .to_body()
      .exact_view(),
    ).exact_view(),
  )
  w.bytes(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  @armor.Message.encode(w.to_bytes().exact_view())
}

///|
/// P5b (c1g6): an OPS promising SHA-256 with a trailing SHA-512 signature
/// over the same data — the signature must be IGNORED for validation
/// (RFC 9580 §5.2.5), surfacing as NotSigned even though it would
/// cryptographically verify.
test "x2 P5b: OPS/signature hash mismatch is NotSigned" {
  let key = generate_ed25519_key("S <s@example.com>")
  let signer = key.primary
  let sig = make_document_signature_with(
    signer,
    x2_payload.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha512,
  )
  let ops = one_pass_sig_for(signer, sig, @primitives.Sha256)
  let (data, status) = verify_inline(
    x2_inline_stream(ops, sig),
    key.to_public(),
  )
  assert_eq(data, x2_payload)
  assert_eq(status, VerifyStatus::NotSigned)
}

///|
/// P5c (c1g6 row pairing): an OPS v3 with a v6 trailing signature — the
/// Table 27 v4 row pairs OPS v3 with a v4 signature only.
test "x2 P5c: OPS v3 + v6 signature is NotSigned" {
  let key = generate_ed25519_v6_key("S6 <s6@example.com>")
  let signer = key.primary
  let sig = make_document_signature_with(
    signer,
    x2_payload.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha256,
  )
  let ops : @packet.OnePassSigPacket = {
    version: 3,
    sig_type: @packet.BinaryDocument,
    hash_algo: @primitives.Sha256.number(),
    pub_algo: signer.public.algo(),
    key_id: signer.public.key_id(),
    salt: Bytes::new(0),
    fingerprint: Bytes::new(0),
    nested: true,
  }
  let (data, status) = verify_inline(
    x2_inline_stream(ops, sig),
    key.to_public(),
  )
  assert_eq(data, x2_payload)
  assert_eq(status, VerifyStatus::NotSigned)
}

///|
/// P5f (c1g7 control): v6 sign_inline — nested flag now always 1 — still
/// roundtrips and pairs OPS v6 with the v6 signature.
test "x2 P5f: v6 sign_inline roundtrip verifies" {
  let key = generate_ed25519_v6_key("S6 <s6@example.com>")
  let msg = sign_inline(x2_payload.exact_view(), key)
  let (data, status) = verify_inline(msg, key.to_public())
  assert_eq(data, x2_payload)
  assert_eq(status, VerifyStatus::Ok)
}

///|
/// P6 helpers: a usage-0 v4 native Ed25519 / v4 native X25519 secret key
/// packet built around a freshly generated pair, with an optional
/// mutation applied to the secret material (checksum corruption / trailing
/// garbage).
fn x2_ed25519_v4_sk(
  mutate : (Array[Byte]) -> Array[Byte],
) -> @packet.SecretKeyPacket raise {
  let kp = @pki.ed25519_generate()
  let mat : Array[Byte] = []
  for b in kp.seed {
    mat.push(b)
  }
  let sum = @packet.session_key_checksum(kp.seed.exact_view())
  mat.push((sum >> 8).to_byte())
  mat.push(sum.to_byte())
  @packet.SecretKeyPacket::{
    public: {
      version: 4,
      creation_time: 0,
      algo: @packet.Ed25519,
      params: [kp.public],
    },
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: Bytes::from_array(mutate(mat)),
    dummy: false,
  }
}

///|
fn x2_x25519_v4_sk(
  mutate : (Array[Byte]) -> Array[Byte],
) -> @packet.SecretKeyPacket raise {
  let kp = @pki.x25519_generate()
  let mat : Array[Byte] = []
  for b in kp.scalar {
    mat.push(b)
  }
  let sum = @packet.session_key_checksum(kp.scalar.exact_view())
  mat.push((sum >> 8).to_byte())
  mat.push(sum.to_byte())
  @packet.SecretKeyPacket::{
    public: {
      version: 4,
      creation_time: 0,
      algo: @packet.X25519,
      params: [kp.public],
    },
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: Bytes::from_array(mutate(mat)),
    dummy: false,
  }
}

///|
/// P6a (c2g5): the Ed25519 native accessor — intact material reads, a
/// corrupted checksum fails, appended bytes fail the exact-length pin.
test "x2 P6a: Ed25519 v4 secret checksum gate" {
  let ok = x2_ed25519_v4_sk(m => m)
  let parts = ed25519_native_secret_parts(ok)
  assert_eq(parts.seed.length(), 32)
  let bad = x2_ed25519_v4_sk(m => {
    m[32] = (m[32].to_int() ^ 0xFF).to_byte()
    m
  })
  assert_true(x2_raises(() => ignore(ed25519_native_secret_parts(bad))))
  let garbage = x2_ed25519_v4_sk(m => {
    m.push(0)
    m.push(0)
    m
  })
  assert_true(x2_raises(() => ignore(ed25519_native_secret_parts(garbage))))
}

///|
/// P6b (c2g5): the X25519 native accessor — same three-way; v6 material
/// (no checksum) stays length-pinned.
test "x2 P6b: X25519 secret checksum gate" {
  let ok = x2_x25519_v4_sk(m => m)
  assert_eq(x25519_native_secret(ok).length(), 32)
  let bad = x2_x25519_v4_sk(m => {
    m[32] = (m[32].to_int() ^ 0x01).to_byte()
    m
  })
  assert_true(x2_raises(() => ignore(x25519_native_secret(bad))))
  let garbage = x2_x25519_v4_sk(m => {
    m.push(0xAA)
    m.push(0xBB)
    m
  })
  assert_true(x2_raises(() => ignore(x25519_native_secret(garbage))))
  // v6 native: no checksum on the wire, but the 32-octet length is exact.
  let kp = @pki.x25519_generate()
  let v6 : @packet.SecretKeyPacket = {
    public: {
      version: 6,
      creation_time: 0,
      algo: @packet.X25519,
      params: [kp.public],
    },
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: kp.scalar.add(Bytes::from_array([0x00])),
    dummy: false,
  }
  assert_true(x2_raises(() => ignore(x25519_native_secret(v6))))
}

///|
/// P6c (c2g5): the ECDH (Curve25519Legacy) accessor — exact consumption:
/// two appended octets after the checksum must break the key.
test "x2 P6c: ECDH v4 secret checksum gate" {
  let ok = build_ecdh_secret_key_packet(0)
  ignore(ecdh_secret_parts(ok))
  let corrupt = {
    ..ok,
    secret_material: ok.secret_material.add(Bytes::from_array([0x00, 0x01])),
  }
  assert_true(x2_raises(() => ignore(ecdh_secret_parts(corrupt))))
}

///|
/// P6d (c2g5): the RSA accessor — appended octets break the alignment
/// guard, a corrupted checksum fails the value check.
test "x2 P6d: RSA v4 secret checksum gate" {
  let key = generate_key("R <r@example.com>")
  let sk = key.primary
  ignore(rsa_secret_parts(sk))
  let garbage = {
    ..sk,
    secret_material: sk.secret_material.add(Bytes::from_array([0x00, 0x02])),
  }
  assert_true(x2_raises(() => ignore(rsa_secret_parts(garbage))))
  let flip_last = {
    ..sk,
    secret_material: sk.secret_material.add(Bytes::new(0)),
  }
  let n = flip_last.secret_material.length()
  let mut corrupted = Bytes::new(0)
  for i in 0..<n {
    if i == n - 1 {
      corrupted = corrupted.add(
        Bytes::from_array([(sk.secret_material[i].to_int() ^ 0x01).to_byte()]),
      )
    } else {
      corrupted = corrupted.add(Bytes::from_array([sk.secret_material[i]]))
    }
  }
  let badsum = { ..sk, secret_material: corrupted, }
  assert_true(x2_raises(() => ignore(rsa_secret_parts(badsum))))
}

///|
/// P6e (c2g5): the EdDSA legacy accessor — checksum corruption and
/// appended octets both refuse; a seed whose first octet is 0x00 arrives
/// MPI-stripped and must still read (pad_left) with the checksum over the
/// full MPI bytes.
test "x2 P6e: EdDSA legacy secret checksum gate" {
  let key = generate_ed25519_key("L <l@example.com>")
  let sk = key.primary
  ignore(eddsa_secret_parts(sk))
  let garbage = {
    ..sk,
    secret_material: sk.secret_material.add(Bytes::from_array([0x00, 0x03])),
  }
  assert_true(x2_raises(() => ignore(eddsa_secret_parts(garbage))))
  // Leading-zero seed: 32-octet seed with a 0x00 first octet, MPI-encoded
  // as 248 bits / 31 octets.
  let kp = @pki.ed25519_generate()
  let seed = Bytes::from_array([0]).add(kp.seed[1:32].to_owned())
  let sw = @packet.Writer::new()
  sw.u16(248)
  sw.bytes(kp.seed[1:32].exact_view())
  let mpi_bytes = sw.to_bytes()
  let w2 = @packet.Writer::new()
  w2.bytes(mpi_bytes.exact_view())
  w2.u16(@packet.session_key_checksum(mpi_bytes.exact_view()))
  let zeroed : @packet.SecretKeyPacket = {
    public: {
      version: 4,
      creation_time: 0,
      algo: @packet.EdDsaLegacy,
      params: [@pki.ed25519_oid(), Bytes::from_array([0x40]).add(kp.public)],
    },
    s2k_usage: 0,
    cipher_algo: 0,
    aead_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: w2.to_bytes(),
    dummy: false,
  }
  let parts = eddsa_secret_parts(zeroed)
  assert_eq(parts.seed, seed)
}

///|
/// P6f: end to end — a primary whose checksum byte was flipped must not
/// sign (the accessor gate fires through the public signing entry).
test "x2 P6f: corrupted checksum key refuses to sign" {
  let key = generate_ed25519_key("L <l@example.com>")
  let sk = key.primary
  let corrupted = {
    ..sk,
    secret_material: {
      let n = sk.secret_material.length()
      let mut out = Bytes::new(0)
      for i in 0..<n {
        if i == n - 1 {
          out = out.add(
            Bytes::from_array([
              (sk.secret_material[i].to_int() ^ 0x01).to_byte(),
            ]),
          )
        } else {
          out = out.add(Bytes::from_array([sk.secret_material[i]]))
        }
      }
      out
    },
  }
  let broken : PrivateKey = { ..key, primary: corrupted, }
  assert_true(x2_raises(() => ignore(sign_detached(b"payload", broken))))
}

///|
fn x2_weak_sig_armored(
  hash : @primitives.HashId,
  hashed : Array[@packet.SigSubpacket],
) -> (PrivateKey, String) raise {
  let key = generate_ed25519_key("W <w@example.com>")
  let signer = key.primary
  let sig : @packet.SignaturePacket = {
    version: 4,
    sig_type: @packet.BinaryDocument,
    pub_algo: signer.public.algo(),
    hash_algo: hash.number(),
    hashed_subpackets: hashed,
    unhashed_subpackets: [
      {
        critical: false,
        sub_type: @packet.SIGSUB_ISSUER_KEY_ID,
        body: signer.public.key_id(),
      },
    ],
    raw_hashed_area: Bytes::new(0),
    fast_hash: 0,
    salt: Bytes::new(0),
    sig_params: [],
  }
  let digest = finish_signed_digest(sig, x2_payload.exact_view())
  let done = finish_signature(sig, signer, hash, digest.exact_view())
  let armored = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, done.to_body().exact_view()).exact_view(),
  )
  (key, armored)
}

///|
fn x2_creation(t : Int32) -> @packet.SigSubpacket {
  {
    critical: false,
    sub_type: @packet.SIGSUB_CREATION_TIME,
    body: Bytes::from_array([
      (t >> 24).to_byte(),
      (t >> 16).to_byte(),
      (t >> 8).to_byte(),
      t.to_byte(),
    ]),
  }
}

///|
/// P7b (c2g7 control): with a creation time ON/after the SHAttered cutoff
/// the same signature is rejected.
test "x2 P7b: SHA-1 sig stamped after the cutoff fails" {
  let (key, armored) = x2_weak_sig_armored(@primitives.Sha1, [
    x2_creation(1577836801),
  ])
  let status = verify_detached(
    x2_payload.exact_view(),
    armored,
    key.to_public(),
  )
  assert_eq(status, VerifyStatus::Failed)
}

///|
/// P7c (c2g7 control): pre-cutoff SHA-1 stays validation-only by policy.
test "x2 P7c: SHA-1 sig stamped before the cutoff validates" {
  let (key, armored) = x2_weak_sig_armored(@primitives.Sha1, [
    x2_creation(1577000000),
  ])
  let status = verify_detached(
    x2_payload.exact_view(),
    armored,
    key.to_public(),
  )
  assert_eq(status, VerifyStatus::Ok)
}

///|
/// P7d (c1g3 control): Ed25519 (native, v6 key) with SHA-224 — digest 28
/// < 256 bits — must fail verification.
test "x2 P7d: Ed25519 + SHA-224 fails the digest gate" {
  let key = generate_ed25519_v6_key("W6 <w6@example.com>")
  let sig = make_document_signature_with(
    key.primary,
    x2_payload.exact_view(),
    @packet.BinaryDocument,
    @primitives.Sha224,
  )
  let armored = @armor.Signature.encode(
    @packet.serialize_packet(@packet.Signature, sig.to_body().exact_view()).exact_view(),
  )
  let status = verify_detached(
    x2_payload.exact_view(),
    armored,
    key.to_public(),
  )
  assert_eq(status, VerifyStatus::Failed)
}

///|
/// P7e (c2g2 control): the issuance gate refuses MD5/SHA-1/RIPEMD-160 on
/// every path that shares make_document_signature_with.
test "x2 P7e: issuance gate refuses weak hashes" {
  let key = generate_ed25519_key("W <w@example.com>")
  assert_true(
    x2_raises(() => {
      ignore(
        make_document_signature_with(
          key.primary,
          x2_payload.exact_view(),
          @packet.BinaryDocument,
          @primitives.Sha1,
        ),
      )
    }),
  )
  assert_true(
    x2_raises(() => {
      ignore(
        make_document_signature_with(
          key.primary,
          x2_payload.exact_view(),
          @packet.BinaryDocument,
          @primitives.Ripemd160,
        ),
      )
    }),
  )
}
