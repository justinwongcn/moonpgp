///|
/// Non-native stub: browsers and wasm runtimes have no TCP. Mail
/// transports are native-only by design (documented limitation).
#cfg(not(target="native"))
pub fn connect_socket(_host : String, _port : Int) -> &Socket raise {
  raise @error.PgpError::PgpError(
    msg="mailnet: TCP requires the native target (no sockets on wasm/js)",
  )
}
