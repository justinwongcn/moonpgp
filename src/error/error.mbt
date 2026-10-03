///|
/// The single error type raised by every package in this module.
pub(all) suberror PgpError {
  PgpError(msg~ : String)
}

///|
/// Show includes the message so test failures are self-explanatory.
pub impl Show for PgpError with fn output(self, logger) {
  match self {
    PgpError(msg~) => logger.write_string("PgpError(\{msg})")
  }
}

///|
/// Raise a `PgpError` with the given message.
pub fn[T] fail(msg : String) -> T raise PgpError {
  raise PgpError(msg~)
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
