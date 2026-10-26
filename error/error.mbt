///|
/// The single error type raised by every package in this module.
///
/// The four variants mark the failure classes a caller can branch on;
/// every variant carries the same human-readable message the library has
/// always raised, so existing message matching keeps working:
///
/// - `PgpError` — everything else: caller argument mistakes, internal
///   invariant violations, and failures that belong to no other class.
/// - `Malformed` — the input data does not parse or violates the format
///   (bad lengths, corrupt tags, unknown structure). The message tells
///   corrupt input from caller error.
/// - `Unsupported` — the input is well-formed but carries an algorithm,
///   version, or feature this library does not implement.
/// - `WrongPassphrase` — a passphrase check failed definitively. Raised
///   when unlocking a key or decrypting a passphrase-protected message
///   with the wrong passphrase. On AEAD-protected key material the same
///   variant also fires for a corrupted key; the message text tells the
///   two cases apart.
///
/// # Example
///
/// Branch on the variant; the message stays available either way.
///
/// ```mbt check
/// test "match picks the variant, message stays available" {
///   let e : @error.PgpError = WrongPassphrase(
///     msg="api: wrong passphrase (checksum failed)",
///   )
///   match e {
///     WrongPassphrase(msg~) =>
///       inspect(msg, content="api: wrong passphrase (checksum failed)")
///     _ => @error.fail("expected WrongPassphrase")
///   }
/// }
/// ```
pub(all) suberror PgpError {
  PgpError(msg~ : String)
  Malformed(msg~ : String)
  Unsupported(msg~ : String)
  WrongPassphrase(msg~ : String)
}

///|
/// Show includes the variant and message so test failures are
/// self-explanatory.
pub impl Show for PgpError with fn output(self, logger) {
  match self {
    PgpError(msg~) => logger.write_string("PgpError(\{msg})")
    Malformed(msg~) => logger.write_string("Malformed(\{msg})")
    Unsupported(msg~) => logger.write_string("Unsupported(\{msg})")
    WrongPassphrase(msg~) => logger.write_string("WrongPassphrase(\{msg})")
  }
}

///|
/// Raise a generic `PgpError` with the given message.
pub fn[T] fail(msg : String) -> T raise PgpError {
  raise PgpError(msg~)
}

///|
/// Raise `Malformed`: the input data does not parse or violates the
/// format.
pub fn[T] malformed(msg : String) -> T raise PgpError {
  raise Malformed(msg~)
}

///|
/// Raise `Unsupported`: the input is well-formed but carries an
/// algorithm, version, or feature this library does not implement.
pub fn[T] unsupported(msg : String) -> T raise PgpError {
  raise Unsupported(msg~)
}

///|
/// Raise `WrongPassphrase`: a passphrase check failed definitively.
pub fn[T] wrong_passphrase(msg : String) -> T raise PgpError {
  raise WrongPassphrase(msg~)
}

///|
/// Unwrap an `Option` that must be present, raising `msg` when it is `None`.
pub fn[T] require(opt : T?, msg : String) -> T raise PgpError {
  match opt {
    Some(v) => v
    None => fail(msg)
  }
}

///|
pub extend PgpError with Show::{to_string, output}
