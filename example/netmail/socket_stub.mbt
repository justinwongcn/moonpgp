///|
/// Non-native stub: browsers and wasm runtimes have no TCP. Mail
/// transports are native-only by design (documented limitation).
#cfg(not(target="native"))
pub fn connect_socket(_host : String, _port : Int32) -> &Socket raise {
  @error.fail("mailnet: TCP requires the native target (no sockets on wasm/js)")
}

///|
#cfg(not(target="native"))
pub fn connect_sock(_host : String, _port : Int32) -> &Sock raise {
  @error.fail("mailnet: TCP requires the native target (no sockets on wasm/js)")
}

///|
#cfg(not(target="native"))
pub fn close_fd_raw(_fd : Int32) -> Unit {
  ()
}
