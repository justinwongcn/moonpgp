///|
/// Encrypted SMTP submission (plan tls-transport §3.3/§3.4): implicit
/// TLS (handshake right after connect, port 465) or STARTTLS (587:
/// plaintext EHLO → STARTTLS → upgrade → second EHLO, RFC 3207) over
/// one POSIX connection, reached through async DNS (the plaintext
/// backend's dotted-quad limit does not apply here).
///
/// AUTH policy upgrade: over an encrypted connection AUTH PLAIN is
/// legitimate for any host — keeping credentials off the wire in the
/// clear is exactly what TLS is for here; the non-local plaintext
/// refusal stays in SmtpTransport. Trust defaults to the OS root
/// store; NoVerification is opt-in only and prints a loud warning.
///
/// Yielding discipline (see fd_sock.mbt): the toolchain's coroutine
/// lowering loses worker-pool wakeups when a suspension happens more
/// than three user frames below `async fn main`, and `errdefer`
/// frames across any suspension are equally fatal. Therefore this
/// transport has exactly TWO suspensions — the DNS resolve and the
/// Tls::client call — both issued DIRECTLY from this function body
/// (never through a helper frame), with nothing but try/catch frames
/// live across them; errdefer ownership starts only after the
/// handshake, when the session is purely synchronous. The fd is
/// closed exactly once on every path, and the TLS object closes
/// BEFORE the fd (Tls::close must precede closing the transport).

///|
/// Trust policy for TLS submission, mirroring the CLI --smtp-trust
/// values. System is the default and the only recommended setting.
/// PemFile pins the PEER certificate exactly (DER equality with the
/// first PEM block of the file) instead of building a custom trust
/// store: @tls's CustomPemFile reads the PEM through the async FS,
/// a suspension the coroutine bug makes unusable at this call depth,
/// and pinning covers the real use cases (self-signed local sinks,
/// known-server pinning) with a strictly verifiable check.
pub(all) enum SmtpTrust {
  System
  PemFile(String)
  Insecure
}

///|
/// Handshake placement: Implicit (port 465 style) or Starttls
/// (port 587 style).
pub(all) enum SmtpTlsMode {
  Implicit
  Starttls
}

///|
fn SmtpTrust::to_trusted_root(self : SmtpTrust) -> @tls.TrustedRoot {
  match self {
    System => @tls.SystemRoot
    // NoVerification + synchronous pin check in
    // verify_peer_certificate — see the enum doc.
    PemFile(_) => @tls.NoVerification
    Insecure => @tls.NoVerification
  }
}

///|
/// Format the resolver's UInt as dotted-quad IPv4 (network order:
/// most significant octet first — verified against 127.0.0.1).
fn ipv4_string(ip : UInt) -> String {
  let a = (ip >> 24) & 0xFF
  let b = (ip >> 16) & 0xFF
  let c = (ip >> 8) & 0xFF
  let d = ip & 0xFF
  "\{a}.\{b}.\{c}.\{d}"
}

///|
/// Extract the DER bytes of the first PEM CERTIFICATE block.
fn first_cert_der(text : String) -> Bytes raise {
  let begin = "-----BEGIN CERTIFICATE-----"
  let end = "-----END CERTIFICATE-----"
  guard text.contains(begin) && text.contains(end) else {
    @error.fail("netmail: no PEM CERTIFICATE block in trust file")
  }
  let b = text.split(begin).collect()[1]
  let body = b.split(end).collect()[0]
  let b64 = StringBuilder()
  for line in body.split("\n") {
    let t = line.trim()
    if t != "" {
      b64.write_stringview(t)
    }
  }
  @base64.decode(b64.to_string())
}

///|
/// PemFile trust: the handshake ran without verification, so pin the
/// peer certificate to the anchor NOW, before any SMTP byte flows.
fn verify_peer_certificate(tls : @tls.Tls, trust : SmtpTrust) -> Unit raise {
  match trust {
    PemFile(path) => {
      let peer = tls.get_peer_certificate()
      guard peer is Some(der) else {
        @error.fail("netmail: server presented no certificate")
      }
      let anchor = first_cert_der(@fs.read_file_to_string(path))
      guard der == anchor else {
        @error.fail(
          "netmail: server certificate does not match the pinned --smtp-trust anchor",
        )
      }
    }
    _ => ()
  }
}

///|
pub(all) struct TlsTransport {
  host : String
  port : Int
  mode : SmtpTlsMode
  trust : SmtpTrust
  ehlo_domain : String
  user : String?
  password : String?
}

///|
// The catch blocks below are load-bearing: errdefer across the two
// suspension points is forbidden (toolchain coroutine bug), so the
// suspend-safe try/catch form is mandatory here.
#cfg(target="native")
#warnings("-fragile_catch_all")
pub async fn TlsTransport::send(
  self : TlsTransport,
  message : String,
  from : String,
  recipients : Array[String],
) -> Unit {
  let auth : (String, String)? = match (self.user, self.password) {
    (Some(u), Some(p)) => Some((u, p))
    (Some(_), None) =>
      @error.fail("smtp: --smtp-user given but --smtp-pass-env not set")
    (None, Some(_)) =>
      @error.fail("smtp: --smtp-pass-env given but --smtp-user not set")
    (None, None) => None
  }
  if self.trust is Insecure {
    eprintln(
      "WARNING: SMTP certificate verification is DISABLED (--smtp-trust none). The session is encrypted, but the server's identity is NOT authenticated — active attackers can intercept the mail.",
    )
  }
  // Suspension point 1: DNS resolve, nothing but this frame across it.
  let addr = @socket.Addr::resolve(
    self.host,
    port=self.port,
    protocol=@socket.OnlyV4,
  )
  let ns = open_native_sock(ipv4_string(addr.ip()), self.port)
  let fd = ns.fd
  match self.mode {
    Implicit => {
      // Suspension point 2: Tls::client stays INLINE in this body —
      // one more async frame (a helper) puts the suspension four user
      // frames from async main, where coroutine resume is broken.
      let tls = @tls.Tls::client(
        FdSock::make(fd),
        host=self.host,
        sni=true,
        trust=self.trust.to_trusted_root(),
      ) catch {
        e => {
          close_fd_raw(fd)
          raise e
        }
      }
      // Purely synchronous from here on. Ownership arms BEFORE the pin
      // check: verify runs no suspension, so errdefer is safe, and a
      // certificate rejection unwinds through the same closes as any
      // later failure (fd/TLS leak, review 2026-10-06 P2).
      let sock : &Sock = AsyncSock::new(tls, fn() { tls.close() })
      errdefer close_fd_raw(fd)
      errdefer Sock::close(sock)
      verify_peer_certificate(tls, self.trust)
      smtp_send(sock, message, from, recipients, self.ehlo_domain, auth)
      Sock::close(sock)
    }
    Starttls => {
      // Plaintext phase over the same fd: the NativeSock here is I/O
      // only and never closed through its own method — the fd's single
      // owner is this function (try/catch pre-handshake, errdefer
      // post-handshake, explicit close on success).
      let plain : &Sock = ns
      let _caps = try {
        smtp_greeting(plain)
        smtp_starttls_ehlo(plain, self.ehlo_domain)
        0
      } catch {
        e => {
          close_fd_raw(fd)
          raise e
        }
      }
      // Suspension point 2 (see Implicit).
      let tls = @tls.Tls::client(
        FdSock::make(fd),
        host=self.host,
        sni=true,
        trust=self.trust.to_trusted_root(),
      ) catch {
        e => {
          close_fd_raw(fd)
          raise e
        }
      }
      // Ownership arms BEFORE the pin check (same reasoning as
      // Implicit): a certificate rejection must close fd + TLS.
      let sock : &Sock = AsyncSock::new(tls, fn() { tls.close() })
      errdefer close_fd_raw(fd)
      errdefer Sock::close(sock)
      verify_peer_certificate(tls, self.trust)
      smtp_session(sock, message, from, recipients, self.ehlo_domain, auth)
      Sock::close(sock)
    }
  }
  close_fd_raw(fd)
}

///|
/// Non-native stub: the TLS transport rides the POSIX socket and the
/// system SSL library — native-only like every mail transport here.
#cfg(not(target="native"))
pub async fn TlsTransport::send(
  _self : TlsTransport,
  _message : String,
  _from : String,
  _recipients : Array[String],
) -> Unit {
  @error.fail("netmail: TLS requires the native target (no sockets on wasm/js)")
}
