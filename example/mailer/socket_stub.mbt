///|
/// Non-native stub: browsers and wasm runtimes have no TCP. The whole
/// SMTP transport is native-only by design (documented limitation).
#cfg(not(target="native"))
fn connect_socket(_host : String, _port : Int) -> &Socket raise {
  raise @error.PgpError::PgpError(
    msg="smtp: the SMTP transport requires the native target (no TCP on wasm/js)",
  )
}
