///|
/// Transport seam shared by the mail examples: one TCP socket, three
/// read disciplines. SMTP uses read_line (UTF-8 text); IMAP needs the
/// byte-faithful read_raw_line/read_exact pair because IMAP literals
/// carry arbitrary octets (8-bit bodies, binary attachments) that must
/// survive a String round-trip untouched. All three disciplines share
/// one internal buffer (LineBuffer), so they may be freely interleaved
/// on the same connection.
pub(open) trait Socket {
  fn write_all(Self, data : Bytes) -> Unit raise
  /// One CRLF-terminated line, terminator stripped (UTF-8 lossy decode).
  fn read_line(Self) -> String raise
  /// One CRLF- or LF-terminated line as raw bytes, terminator stripped.
  fn read_raw_line(Self) -> Bytes raise
  /// Exactly `n` octets, byte-faithful, independent of chunking.
  fn read_exact(Self, n : Int) -> Bytes raise
  fn close(Self) -> Unit
}

///|
/// Local-connection test shared by the transports' plaintext policies:
/// AUTH/LOGIN is refused to any host outside this set unless the user
/// passes the explicit opt-in flag.
pub fn is_local_host(host : String) -> Bool {
  host == "127.0.0.1" || host == "localhost" || host == "::1"
}
