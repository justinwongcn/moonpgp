///|
/// ECDH (Curve25519Legacy) public-key encryption for session keys,
/// RFC 9580 §5.1.5 and §11.5: one-pass X25519 + SHA-256 KDF + AES key
/// wrap (RFC 3394).

///|
/// Curve25519Legacy secret parts: the wire secret MPI is a big-endian
/// 255-bit clamped scalar; convert to the native little-endian form.
fn ecdh_secret_parts(p : @packet.SecretKeyPacket) -> @pki.X25519SecretKey raise {
  guard p.s2k_usage == 0 else {
    raise @error.PgpError::PgpError(
      msg="api: secret key material is locked; unlock it first",
    )
  }
  guard p.public.algo() == @packet.Ecdh else {
    raise @error.PgpError::PgpError(msg="api: not an ECDH key")
  }
  let r = @packet.Reader::new(p.secret_material.exact_view())
  let mpi_value = r.read_mpi()
  @pki.x25519_secret_of_wire_mpi(mpi_value.exact_view())
}

///|
/// The ECDH KDF parameter string for a v4 recipient key packet
/// (RFC 9580 §11.5): length-prefixed curve OID || algorithm ID ||
/// KDF-params field (as stored) || "Anonymous Sender    " ||
/// 20-octet v4 fingerprint of the encryption subkey.
fn ecdh_kdf_param(pub_packet : @packet.PublicKeyPacket) -> Bytes raise {
  let params = pub_packet.params()
  guard params.length() == 3 else {
    raise @error.PgpError::PgpError(msg="api: bad ECDH public parameters")
  }
  // Wire order: OID, point, KDF params (RFC 9580 §5.5.5.6).
  let oid = params[0]
  let kdf_field = params[2]
  guard kdf_field.length() == 4 else {
    raise @error.PgpError::PgpError(msg="api: bad ECDH KDF parameters")
  }
  let fp = pub_packet.fingerprint()
  guard fp.length() == 20 else {
    raise @error.PgpError::PgpError(msg="api: ECDH requires a v4 fingerprint")
  }
  let w = @packet.Writer::new()
  w.bytes(oid.exact_view())
  w.u8(18)
  w.bytes(kdf_field.exact_view())
  w.bytes(@pki.ecdh_anonymous_sender().exact_view())
  w.bytes(fp.exact_view())
  w.to_bytes()
}

///|
/// The symmetric algorithm id carried in the key's KDF parameters
/// (the key-wrap KEK size selector).
fn ecdh_kdf_sym_algo(pub_packet : @packet.PublicKeyPacket) -> Int raise {
  // Index only after the guards: the packet layer accepts keys whose KDF
  // field is shorter than 4 octets, and callers hand them straight here.
  let params = pub_packet.params()
  guard params.length() == 3 else {
    raise @error.PgpError::PgpError(msg="api: bad ECDH public parameters")
  }
  let kdf_field = params[2]
  guard kdf_field.length() >= 4 else {
    raise @error.PgpError::PgpError(msg="api: bad ECDH KDF parameters")
  }
  kdf_field[3].to_int()
}

///|
/// Derive the KEK from the shared secret and the recipient key packet.
fn ecdh_kek(
  shared : BytesView,
  pub_packet : @packet.PublicKeyPacket,
) -> Bytes raise {
  let sym = ecdh_kdf_sym_algo(pub_packet)
  let kek_len = match @primitives.cipher_algo_of_number(sym) {
    Some(a) => a.key_size()
    None =>
      raise @error.PgpError::PgpError(
        msg="api: unsupported ECDH KEK cipher \{sym}",
      )
  }
  @pki.ecdh_kdf_sha256(
    shared,
    ecdh_kdf_param(pub_packet).exact_view(),
    kek_len * 8,
  )
}

///|
/// PKCS#5 padding to 8-octet granularity (RFC 9580 §11.5 via RFC 8018).
fn pkcs5_pad8(data : BytesView) -> Bytes {
  let n = 8 - data.length() % 8
  let out : Array[Byte] = []
  for b in data {
    out.push(b)
  }
  for _ in 0..<n {
    out.push(n.to_byte())
  }
  Bytes::from_array(out)
}

///|
/// Strip and verify PKCS#5 padding.
fn pkcs5_unpad8(data : BytesView) -> Bytes raise {
  guard data.length() > 0 else {
    raise @error.PgpError::PgpError(msg="api: empty padded payload")
  }
  let n = data[data.length() - 1].to_int()
  guard n >= 1 && n <= 8 && data.length() >= n else {
    raise @error.PgpError::PgpError(msg="api: bad session key padding")
  }
  for i = data.length() - n; i < data.length(); i = i + 1 {
    guard data[i].to_int() == n else {
      raise @error.PgpError::PgpError(msg="api: bad session key padding")
    }
  }
  data[0:data.length() - n].to_owned()
}

///|
/// Native 32-octet point value from a public key packet (an MPI value
/// of 0x40 || X, second param after the OID).
fn ecdh_native_point(pub_packet : @packet.PublicKeyPacket) -> Bytes raise {
  let point = pub_packet.params()[1]
  guard point.length() == 33 && point[0] == b'\x40' else {
    raise @error.PgpError::PgpError(msg="api: bad Curve25519Legacy point")
  }
  point[1:point.length()].to_owned()
}

///|
/// ECDH-encrypt the session key to `recipient_pub`: fresh ephemeral
/// scalar, X25519 shared secret, §11.4 KDF, RFC 3394 wrap. Returns the
/// ephemeral point MPI value (0x40 || X) and the wrapped key.
fn ecdh_wrap_session_key(
  recipient_pub : @packet.PublicKeyPacket,
  session_key : BytesView,
  sym_algo : @primitives.CipherAlgo,
) -> (Bytes, Bytes) raise {
  let eph = @pki.x25519_generate()
  let peer = ecdh_native_point(recipient_pub)
  let shared = @pki.x25519_shared_secret(
    eph.scalar.exact_view(),
    peer.exact_view(),
  )
  let kek = ecdh_kek(shared.exact_view(), recipient_pub)
  let m = @packet.Writer::new()
  m.u8(sym_algo.number())
  m.bytes(session_key)
  m.u16(@packet.session_key_checksum(session_key))
  let wrapped = @cipher.aes_key_wrap(
    kek.exact_view(),
    pkcs5_pad8(m.to_bytes().exact_view()).exact_view(),
  )
  let point = Bytes::from_array([0x40]).add(eph.public)
  (point, wrapped)
}

///|
/// ECDH-decrypt a PKESK with an unlocked Curve25519Legacy secret key.
/// Returns (symmetric algorithm id, session key).
fn ecdh_unwrap_session_key(
  pkesk : @packet.PkeskPacket,
  sk : @packet.SecretKeyPacket,
) -> (Int, Bytes) raise {
  let secret = ecdh_secret_parts(sk)
  let eph = pkesk.ecdh_ephemeral()
  guard eph.length() == 33 && eph[0] == b'\x40' else {
    raise @error.PgpError::PgpError(msg="api: bad ECDH ephemeral point")
  }
  let shared = @pki.x25519_shared_secret(
    secret.scalar.exact_view(),
    eph[1:eph.length()].exact_view(),
  )
  let kek = ecdh_kek(shared.exact_view(), sk.public)
  let m = pkcs5_unpad8(
    @cipher.aes_key_unwrap(kek.exact_view(), pkesk.encrypted().exact_view()).exact_view(),
  )
  guard m.length() >= 3 + 16 else {
    raise @error.PgpError::PgpError(msg="api: session key payload too short")
  }
  let algo = m[0].to_int()
  let key = m[1:m.length() - 2].to_owned()
  let want = (m[m.length() - 2].to_int() << 8) | m[m.length() - 1].to_int()
  guard @packet.session_key_checksum(key.exact_view()) == want else {
    raise @error.PgpError::PgpError(msg="api: session key checksum mismatch")
  }
  (algo, key)
}

///|
/// Build a transferable ECDH (Curve25519Legacy) secret subkey packet.
/// KDF parameters: size 3, reserved 0x01, SHA-256 (id 8) hash,
/// AES-128 (id 7) wrap — the exact form GnuPG writes for cv25519 keys.
fn build_ecdh_secret_key_packet(
  creation : Int,
) -> @packet.SecretKeyPacket raise {
  let x = @pki.x25519_generate()
  let point = Bytes::from_array([0x40]).add(x.public)
  // Params in wire order (RFC 9580 §5.5.5.6): length-prefixed OID,
  // point (MPI on the wire), KDF params (length octet + reserved +
  // hash + sym).
  let params : Array[Bytes] = [
    @pki.curve25519_oid(),
    point,
    Bytes::from_array([0x03, 0x01, 0x08, 0x07]),
  ]
  let pub_packet : @packet.PublicKeyPacket = {
    version: 4,
    creation_time: creation,
    algo: @packet.Ecdh,
    params,
  }
  // Secret material: big-endian 255-bit MPI of the clamped scalar plus
  // the 2-octet checksum.
  let sw = @packet.Writer::new()
  let wire = x.wire_mpi()
  sw.u16(255)
  sw.bytes(wire[2:wire.length()].exact_view())
  let mpi_bytes = sw.to_bytes()
  let w2 = @packet.Writer::new()
  w2.bytes(mpi_bytes.exact_view())
  w2.u16(@packet.session_key_checksum(mpi_bytes.exact_view()))
  @packet.SecretKeyPacket::{
    public: pub_packet,
    s2k_usage: 0,
    cipher_algo: 0,
    s2k_spec: Bytes::new(0),
    iv: Bytes::new(0),
    secret_material: w2.to_bytes(),
    dummy: false,
  }
}
