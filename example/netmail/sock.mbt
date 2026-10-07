///|
/// Async transport seam for the SMTP state machine — the async sibling
/// of `Socket`: the same three disciplines (write_all / read_line /
/// close), so one machine programs every backend. Backends per plan
/// tls-transport §3.2: the POSIX FFI wrapped as sync work inside async
/// bodies (PosixSock, i.e. NativeSock's second impl) and the TLS stack
/// (AsyncSock over @socket.Tcp / @tls.Tls). IMAP keeps the sync Socket
/// seam: read_raw_line/read_exact never fire in SMTP flows.
pub(open) trait Sock {
  async fn write_all(Self, data : Bytes) -> Unit
  /// One CRLF-terminated line, terminator stripped (UTF-8 lossy decode).
  async fn read_line(Self) -> String
  fn close(Self) -> Unit
}
