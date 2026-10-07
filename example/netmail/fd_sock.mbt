///|
/// Blocking @io.Reader + @io.Writer facade over a POSIX fd (plan
/// tls-transport §3.2 PosixSock). The toolchain's coroutine lowering
/// mishandles resumption when an await happens inside a
/// dictionary-dispatched async call, so the entire TLS session runs
/// WITHOUT yielding: @tls.Tls drives its handshake and record reads
/// through this adapter, whose _direct_read blocks the executor on
/// recv (SO_RCVTIMEO bounds the wait) — sync work inside async bodies,
/// the same discipline as the plaintext POSIX backend. Only the DNS
/// resolution ahead of the connection ever truly suspends.
///
/// The @io.ReaderBuffer must be STABLE across calls: the async TLS
/// Transport uses it as its wire buffer (enlarge/read/len accounting
/// span multiple calls). That type is internal to moonbitlang/async,
/// but the @io.Reader trait contractually requires exposing it —
/// implementing the trait is impossible without it, hence the
/// silenced internal-API alerts for this file.

///|
#cfg(target="native")
#warnings("-alert_internal")
priv struct FdSock {
  fd : Int
  rb : @io.ReaderBuffer
}

///|
#cfg(target="native")
#warnings("-alert_internal")
fn FdSock::make(fd : Int) -> FdSock {
  { fd, rb: @io.ReaderBuffer::new(), }
}

///|
#cfg(target="native")
impl @io.Reader for FdSock with fn _get_internal_buffer(self) {
  self.rb
}

///|
#cfg(target="native")
impl @io.Reader for FdSock with fn _direct_read(self, buf, offset~, max_len~) -> Int {
  // recv writes at the base pointer only, so read into scratch and
  // blit when the caller asks for a non-zero offset (the async TLS
  // Transport appends into its wire buffer this way).
  guard max_len >= 0 else { @error.fail("netmail: negative tls read length") }
  let tmp : FixedArray[Byte] = FixedArray::make(max_len, b'\x00')
  let n = c_recv(self.fd, tmp, max_len, 0)
  if n < 0 {
    c_perror(b"moonpgp-mailnet")
    @error.fail("netmail: tls transport read failed")
  }
  if n > 0 {
    tmp.blit_to(buf, src_offset=0, dst_offset=offset, len=n)
  }
  // n == 0: clean EOF, mirroring the async backend's 0-is-EOF contract.
  n
}

///|
#cfg(target="native")
impl @io.Writer for FdSock with fn write_once(self, data, offset~, len~) -> Int {
  // The caller may hand us a view with offset > 0 into a larger
  // buffer, so ALWAYS slice off the front before sending; partial-write
  // retries copy the unsent tail (see NativeSock).
  let mut off = offset
  let end = offset + len
  while off < end {
    // The caller may hand us a view with offset > 0 into a larger
    // buffer, so ALWAYS slice off the front before sending (Bytes
    // needs a contiguous pointer for the FFI call); partial-write
    // retries copy the unsent tail (see NativeSock). BytesView offers
    // no copy-free way back to the backing Bytes, so even the
    // offset-0 path copies — accepted, TLS writes are 16 KiB records
    // against blocking syscalls.
    let chunk = data[off:end].to_owned()
    let sent = c_send(self.fd, chunk, end - off, 0)
    guard sent > 0 else {
      c_perror(b"moonpgp-mailnet")
      @error.fail("netmail: tls transport write failed")
    }
    off = off + sent
  }
  len
}
