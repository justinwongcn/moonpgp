///|
/// Async Sock adapter over the TLS session's `@tls.Tls` (plan
/// tls-transport §3.2): one
/// line-buffered implementation whose read_line is byte-for-byte the
/// sync LineBuffer discipline — per-byte lossy decode, CRLF strip,
/// refill only when fully drained. close is a stored closure because
/// backends differ (Tls::close must run before the underlying
/// transport closes) and an idempotence flag so the close-once
/// ownership transfer at the STARTTLS upgrade cannot turn into a
/// double close.

///|
priv struct AsyncSock[R] {
  rw : R
  buf : FixedArray[Byte]
  mut rstart : Int
  mut rend : Int
  close_fn : () -> Unit
  mut closed : Bool
}

///|
fn[R] AsyncSock::new(rw : R, close_fn : () -> Unit) -> AsyncSock[R] {
  {
    rw,
    buf: FixedArray::make(4096, b'\x00'),
    rstart: 0,
    rend: 0,
    close_fn,
    closed: false,
  }
}

///|
/// Refill from the underlying transport; raises at EOF and errors.
/// Only ever called with the buffer fully drained (@io.Reader::read
/// returns 0 at EOF and raises transport errors, matching the sync
/// fill's negative-is-error policy).

///|
async fn[R : @io.Reader] AsyncSock::refill(self : AsyncSock[R]) -> Unit {
  self.rstart = 0
  self.rend = 0
  let n = @io.Reader::read(self.rw, self.buf)
  guard n > 0 else {
    @error.fail("netmail: connection closed by server mid-reply")
  }
  self.rend = n
}

///|
impl[R : @io.Reader + @io.Writer] Sock for AsyncSock[R] with fn write_all(
  self : AsyncSock[R],
  data : Bytes,
) -> Unit raise {
  @io.Writer::write(self.rw, data)
}

///|
/// Ported verbatim from LineBuffer::read_line: UTF-8 lossy decode of
/// one CRLF-terminated line (every byte maps to itself via to_char,
/// invalid code units become '?').

///|
impl[R : @io.Reader + @io.Writer] Sock for AsyncSock[R] with fn read_line(
  self : AsyncSock[R],
) -> String raise {
  let sb = StringBuilder()
  while true {
    while self.rstart < self.rend {
      let v = self.buf[self.rstart].to_int()
      self.rstart = self.rstart + 1
      if v == 10 {
        let s = sb.to_string()
        if s.has_suffix("\r") {
          return s[0:s.length() - 1].to_owned()
        }
        return s
      }
      match v.to_char() {
        Some(c) => sb.write_char(c)
        None => sb.write_char('?')
      }
    }
    self.refill()
  } nobreak {
    // Unreachable: every exit is a return. The nobreak arm satisfies the
    // typechecker, which does not treat `while true` as diverging (E4108).
    abort("netmail: unreachable")
  }
}

///|
impl[R : @io.Reader + @io.Writer] Sock for AsyncSock[R] with fn close(
  self : AsyncSock[R],
) -> Unit {
  if self.closed {
    return
  }
  self.closed = true
  (self.close_fn)()
}
