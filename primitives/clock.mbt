///|
/// Seconds since the Unix epoch, from the platform wall clock.
///
/// Native (the primary target for this module) reads the platform clock
/// through libc. Non-native targets currently fall back to a fixed epoch;
/// key creation times there are placeholder values (documented limitation
/// — no portable clock API exists in core/x yet).
#cfg(target="native")
extern "c" fn c_time(t : Int64) -> Int64 = "time"

///|
#cfg(target="native")
pub fn unix_now() -> Int64 {
  c_time(0)
}

///|
#cfg(not(target="native"))
pub fn unix_now() -> Int64 {
  0L
}
