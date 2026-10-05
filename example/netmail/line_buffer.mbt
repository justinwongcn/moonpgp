///|
/// Shared single-buffer reader behind the Socket read disciplines.
/// Invariant (byte-safety): refill happens ONLY when the buffer is
/// fully drained (rstart >= rend), so switching between read_line /
/// read_raw_line / read_exact on one connection never discards
/// buffered octets. `fill` returns the count of octets read; a
/// NEGATIVE count signals a transport error and 0 signals EOF, so the
/// error policy stays uniform here while the native backend perrors
/// in its own closure. Native-only because only the native backend
/// constructs LineBuffer.

///|
#cfg(target="native")
priv struct LineBuffer {
  buf : FixedArray[Byte]
  mut rstart : Int
  mut rend : Int
  fill : (FixedArray[Byte]) -> Int
}

///|
/// Ported verbatim from the pre-mailnet mailer read_line: UTF-8 lossy
/// decode of one CRLF-terminated line.

///|
#cfg(target="native")
fn LineBuffer::read_line(self : LineBuffer) -> String raise {
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
  }
  abort("mailnet: unreachable")
}

///|
/// One line as raw bytes, CRLF or LF terminator stripped. A bare CR
/// inside the line is preserved (it is data, not a terminator).

///|
#cfg(target="native")
fn LineBuffer::read_raw_line(self : LineBuffer) -> Bytes raise {
  let out : Array[Byte] = []
  let mut pending_cr = false
  while true {
    while self.rstart < self.rend {
      let v = self.buf[self.rstart]
      self.rstart = self.rstart + 1
      if v == b'\n' {
        return Bytes::from_array(out)
      }
      if pending_cr {
        out.push(b'\r')
      }
      if v == b'\r' {
        pending_cr = true
      } else {
        out.push(v)
        pending_cr = false
      }
    }
    self.refill()
  }
  abort("mailnet: unreachable")
}

///|
/// Exactly n octets regardless of how the transport chunks them.

///|
#cfg(target="native")
fn LineBuffer::read_exact(self : LineBuffer, n : Int) -> Bytes raise {
  guard n >= 0 else {
    raise @error.PgpError::PgpError(msg="mailnet: negative read_exact \{n}")
  }
  let out : Array[Byte] = []
  let mut got = 0
  while got < n {
    if self.rstart < self.rend {
      out.push(self.buf[self.rstart])
      self.rstart = self.rstart + 1
      got = got + 1
    } else {
      self.refill()
    }
  }
  Bytes::from_array(out)
}

///|
/// Refill from the underlying transport; raises at EOF and errors.
/// Only ever called with the buffer fully drained.

///|
#cfg(target="native")
fn LineBuffer::refill(self : LineBuffer) -> Unit raise {
  self.rstart = 0
  self.rend = 0
  let n = (self.fill)(self.buf)
  if n < 0 {
    raise @error.PgpError::PgpError(msg="mailnet: recv failed")
  }
  guard n > 0 else {
    raise @error.PgpError::PgpError(
      msg="mailnet: connection closed by server mid-reply",
    )
  }
  self.rend = n
}
