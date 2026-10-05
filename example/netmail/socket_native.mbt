///|
/// POSIX socket backend for the Socket seam (native target only).
/// Lessons from the review probes are baked in: per-OS sockaddr_in
/// layouts, manual big-endian port (no htons double-swap),
/// signal(SIGPIPE, SIG_IGN), SO_RCVTIMEO via dual setsockopt attempts
/// (macOS and Linux disagree on level/name), and perror-based
/// diagnostics (errno is not portably readable).

///|
#cfg(target="native")
#borrow(addr)
extern "c" fn c_connect(fd : Int, addr : Bytes, len : Int) -> Int = "connect"

///|
#cfg(target="native")
extern "c" fn c_socket(domain : Int, tp : Int, protocol : Int) -> Int = "socket"

///|
#cfg(target="native")
#borrow(buf)
extern "c" fn c_recv(
  fd : Int,
  buf : FixedArray[Byte],
  len : Int,
  flags : Int,
) -> Int = "recv"

///|
#cfg(target="native")
#borrow(data)
extern "c" fn c_send(fd : Int, data : Bytes, len : Int, flags : Int) -> Int = "send"

///|
#cfg(target="native")
extern "c" fn c_close(fd : Int) -> Int = "close"

///|
#cfg(target="native")
#borrow(opt)
extern "c" fn c_setsockopt(
  fd : Int,
  level : Int,
  name : Int,
  opt : Bytes,
  len : Int,
) -> Int = "setsockopt"

///|
#cfg(target="native")
#borrow(msg)
extern "c" fn c_perror(msg : Bytes) -> Unit = "perror"

///|
#cfg(target="native")
extern "c" fn c_signal(sig : Int, handler : Int64) -> Int64 = "signal"

///|
#cfg(target="native")
#borrow(buf)
extern "c" fn c_uname(buf : FixedArray[Byte]) -> Int = "uname"

///|
/// DNS is out of scope: dotted-quad IPv4 only (localhost maps to
/// 127.0.0.1). Everything else raises with guidance.
#cfg(target="native")
fn parse_ipv4(host : String) -> (Byte, Byte, Byte, Byte) raise {
  let h = if host == "localhost" { "127.0.0.1" } else { host }
  let parts : Array[StringView] = h.split(".").collect()
  guard parts.length() == 4 else {
    raise @error.PgpError::PgpError(
      msg="mailnet: only dotted-quad IPv4 hosts are supported (no DNS); got '\{host}'",
    )
  }
  let out : Array[Byte] = []
  for p in parts {
    let v = parse_u8(p)
    out.push(v.to_byte()) |> ignore
  }
  (out[0], out[1], out[2], out[3])
}

///|
#cfg(target="native")
fn parse_u8(s : StringView) -> Int raise {
  guard s.length() >= 1 && s.length() <= 3 else {
    raise @error.PgpError::PgpError(msg="mailnet: bad IPv4 octet '\{s}'")
  }
  let mut v = 0
  for c in s {
    let d = c.to_int() - 48
    guard d >= 0 && d <= 9 else {
      raise @error.PgpError::PgpError(msg="mailnet: bad IPv4 octet '\{s}'")
    }
    v = v * 10 + d
  }
  guard v <= 255 else {
    raise @error.PgpError::PgpError(
      msg="mailnet: IPv4 octet out of range '\{s}'",
    )
  }
  v
}

///|
/// True when the machine is macOS (utsname.sysname starts with
/// "Darwin"): sockaddr_in carries sin_len as byte 0 there, while Linux
/// expects sin_family as a u16 at bytes 0-1. uname failure defaults to
/// the Linux layout.
#cfg(target="native")
fn is_darwin() -> Bool {
  // macOS sizeof(struct utsname) = 1280 (C-verified); the kernel fills
  // the whole struct — a smaller buffer corrupts adjacent GC heap.
  let buf = FixedArray::make(1280, b'\x00')
  if c_uname(buf) < 0 {
    return false
  }
  let want : Array[Byte] = [b'D', b'a', b'r', b'w', b'i', b'n']
  for k in 0..<want.length() {
    if buf[k] != want[k] {
      return false
    }
  }
  true
}

///|
#cfg(target="native")
priv struct NativeSock {
  fd : Int
  lb : LineBuffer
}

///|
/// Build a connected socket: SIGPIPE ignored, receive timeout
/// attempted (dual setsockopt — macOS and Linux disagree on the level
/// and option name; failures are ignored as best-effort).
#cfg(target="native")
pub fn connect_socket(host : String, port : Int) -> &Socket raise {
  guard port > 0 && port <= 65535 else {
    raise @error.PgpError::PgpError(msg="mailnet: port out of range \{port}")
  }
  c_signal(13, 1L) |> ignore
  let (a0, a1, a2, a3) = parse_ipv4(host)
  let fd = c_socket(2, 1, 0)
  guard fd >= 0 else {
    c_perror(b"moonpgp-mailnet")
    raise @error.PgpError::PgpError(msg="mailnet: socket() failed")
  }
  // SO_RCVTIMEO: macOS (level 0xffff, name 0x1006) vs Linux (level 1,
  // name 20); try both, ignore rejections — a missed timeout only
  // means a hang on a silent server instead of a wrong option.
  let tv = Bytes::from_array([
    b'\x1e', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
  ])
  c_setsockopt(fd, 0xffff, 0x1006, tv, 16) |> ignore
  c_setsockopt(fd, 1, 20, tv, 16) |> ignore
  // sockaddr_in, 16 bytes; port in network byte order (manual BE —
  // see HANDOFF 8.4 on the htons double-swap trap)
  let p_hi = ((port >> 8) & 0xFF).to_byte()
  let p_lo = (port & 0xFF).to_byte()
  let sa = if is_darwin() {
    Bytes::from_array([
      b'\x10', b'\x02', p_hi, p_lo, a0, a1, a2, a3, b'\x00', b'\x00', b'\x00', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\x00',
    ])
  } else {
    Bytes::from_array([
      b'\x02', b'\x00', p_hi, p_lo, a0, a1, a2, a3, b'\x00', b'\x00', b'\x00', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\x00',
    ])
  }
  let cr = c_connect(fd, sa, 16)
  if cr < 0 {
    c_perror(b"moonpgp-mailnet")
    c_close(fd) |> ignore
    raise @error.PgpError::PgpError(
      msg="mailnet: connect to \{host}:\{port} failed (see stderr)",
    )
  }
  let fill = fn(buf : FixedArray[Byte]) -> Int {
    let n = c_recv(fd, buf, buf.length(), 0)
    if n < 0 {
      c_perror(b"moonpgp-mailnet")
    }
    n
  }
  NativeSock::{
    fd,
    lb: LineBuffer::{
      buf: FixedArray::make(4096, b'\x00'),
      rstart: 0,
      rend: 0,
      fill,
    },
  }
}

///|
#cfg(target="native")
impl Socket for NativeSock with fn write_all(self, data : Bytes) -> Unit raise {
  let n = data.length()
  let mut off = 0
  while off < n {
    let sent = if off == 0 {
      c_send(self.fd, data, n, 0)
    } else {
      c_send(self.fd, data[off:n].to_owned(), n - off, 0)
    }
    guard sent > 0 else {
      c_perror(b"moonpgp-mailnet")
      raise @error.PgpError::PgpError(msg="mailnet: send failed mid-write")
    }
    off = off + sent
  }
}

///|
#cfg(target="native")
impl Socket for NativeSock with fn read_line(self) -> String raise {
  self.lb.read_line()
}

///|
#cfg(target="native")
impl Socket for NativeSock with fn read_raw_line(self) -> Bytes raise {
  self.lb.read_raw_line()
}

///|
#cfg(target="native")
impl Socket for NativeSock with fn read_exact(self, n : Int) -> Bytes raise {
  self.lb.read_exact(n)
}

///|
#cfg(target="native")
impl Socket for NativeSock with fn close(self) -> Unit {
  c_close(self.fd) |> ignore
}
