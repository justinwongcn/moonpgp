///|
/// RFC 5322 mail assembly: headers, date, addresses. This package only
/// COMPOSES messages — transport (SMTP) lives in example/mailer by
/// design, so the library boundary stays "cryptography + assembly".

///|
/// An RFC 5322 mailbox: optional display name plus the addr-spec.
pub(all) struct MailAddress {
  display_name : String
  addr : String
} derive(Debug)

///|
/// Header values are ASCII-only this generation (RFC 2047/6532 are not
/// implemented): anything non-ASCII, or any CR/LF (header injection),
/// fails fast instead of producing a corrupt message.
fn require_ascii(s : String, what : String) -> Unit raise {
  for c in s {
    let v = c.to_int()
    // control characters (incl. CR/LF) and non-ASCII all fail fast:
    // strict MTAs reject them and they weaken the injection story
    if v < 32 || v > 127 {
      raise @error.PgpError::PgpError(
        msg="mail: non-ASCII or control character in \{what} (RFC 2047 not supported)",
      )
    }
  }
}

///|
/// Envelope/header addr-spec hygiene (RFC 5321 §4.1.1): the characters
/// that make an addr-spec structurally invalid or injectable are
/// rejected outright; an address without '@' is not an address.
fn validate_addr_spec(addr : String) -> Unit raise {
  for c in addr {
    let v = c.to_int()
    if v < 33 ||
      v > 126 ||
      c == '<' ||
      c == '>' ||
      c == ',' ||
      c == ';' ||
      c == '"' ||
      c == '\\' {
      raise @error.PgpError::PgpError(
        msg="mail: invalid character in address '\{addr}'",
      )
    }
  }
  guard addr.contains("@") else {
    raise @error.PgpError::PgpError(msg="mail: address without '@': '\{addr}'")
  }
}

///|
/// RFC 5322 §3.2.3 atext: the only characters allowed unquoted in a
/// display name. Notably space and dot are NOT atext.
fn is_atext(c : Char) -> Bool {
  let v = c.to_int()
  (v >= 0x41 && v <= 0x5A) ||
  (v >= 0x61 && v <= 0x7A) ||
  (v >= 0x30 && v <= 0x39) ||
  c == '!' ||
  c == '#' ||
  c == '$' ||
  c == '%' ||
  c == '&' ||
  c == '\'' ||
  c == '*' ||
  c == '+' ||
  c == '-' ||
  c == '/' ||
  c == '=' ||
  c == '?' ||
  c == '^' ||
  c == '_' ||
  c == '`' ||
  c == '{' ||
  c == '|' ||
  c == '}' ||
  c == '~'
}

///|
/// "Name <a@b>" per RFC 5322 §3.4: display names containing anything
/// outside atext (including spaces and dots) are quoted-string encoded
/// with `"`/`\` escapes.
pub fn format_address(a : MailAddress) -> String raise {
  require_ascii(a.addr, "address")
  require_ascii(a.display_name, "display name")
  validate_addr_spec(a.addr)
  guard a.addr != "" else {
    raise @error.PgpError::PgpError(msg="mail: empty address")
  }
  if a.display_name == "" {
    return a.addr
  }
  let mut quoted = false
  for c in a.display_name {
    if !is_atext(c) {
      quoted = true
    }
  }
  if !quoted {
    return "\{a.display_name} <\{a.addr}>"
  }
  "\"\{escape_quoted(a.display_name)}\" <\{a.addr}>"
}

///|
let week_days : Array[String] = [
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
]

///|
let month_names : Array[String] = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

///|
fn pad2(v : Int) -> String {
  if v < 10 {
    "0\{v}"
  } else {
    "\{v}"
  }
}

///|
/// Days-since-epoch to (year, month, day) — Howard Hinnant's
/// civil_from_days, valid across the full Int64 range including
/// pre-1970 dates. Int64 division truncates toward zero, which is why
/// rfc5322_date normalizes negative remainders before calling.
fn civil_from_days(z0 : Int64) -> (Int, Int, Int) {
  let z = z0 + 719468L
  let era = (if z >= 0L { z } else { z - 146096L }) / 146097L
  let doe = z - era * 146097L
  let yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
  let y0 = yoe + era * 400L
  let doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
  let mp = (5L * doy + 2L) / 153L
  let d = (doy - (153L * mp + 2L) / 5L + 1L).to_int()
  let m = (if mp < 10L { mp + 3L } else { mp - 9L }).to_int()
  let y = (if m <= 2 { y0 + 1L } else { y0 }).to_int()
  (y, m, d)
}

///|
fn i64_le_bytes(v : Int64) -> Bytes {
  Bytes::from_array([
    (v & 0xFF).to_byte(),
    ((v >> 8) & 0xFF).to_byte(),
    ((v >> 16) & 0xFF).to_byte(),
    ((v >> 24) & 0xFF).to_byte(),
    ((v >> 32) & 0xFF).to_byte(),
    ((v >> 40) & 0xFF).to_byte(),
    ((v >> 48) & 0xFF).to_byte(),
    ((v >> 56) & 0xFF).to_byte(),
  ])
}

///|
/// Local zone offset in minutes east of UTC, via libc localtime_r.
/// tm_gmtoff sits at byte 40 in the 64-bit struct tm of both macOS and
/// glibc (9 ints, then the long) — verified against `date +%z` on this
/// machine; non-native targets return 0 (documented placeholder, same
/// convention as primitives/clock.mbt).
#cfg(target="native")
#borrow(t, buf)
extern "c" fn c_localtime_r(t : Bytes, buf : FixedArray[Byte]) -> Int = "localtime_r"

///|
#cfg(target="native")
pub fn local_tz_offset_minutes(now_unix : Int64) -> Int raise {
  let tm = FixedArray::make(64, b'\x00')
  let r = c_localtime_r(i64_le_bytes(now_unix), tm)
  guard r != 0 else {
    raise @error.PgpError::PgpError(msg="mail: localtime_r failed")
  }
  let mut gm : Int64 = 0L
  for k in 0..<8 {
    gm = gm | (tm[40 + k].to_int().to_int64() << (8 * k))
  }
  (gm / 60L).to_int()
}

///|
#cfg(not(target="native"))
pub fn local_tz_offset_minutes(_now_unix : Int64) -> Int {
  0
}

///|
/// RFC 5322 §3.3 date-time, e.g. "Fri, 02 Oct 2026 10:00:00 +0800".
/// The zone offset is minutes east of UTC (covers half-hour zones like
/// +0545); negative offsets format as -0730.
pub fn rfc5322_date(now_unix : Int64, tz_offset_minutes : Int) -> String {
  // `local` is a reserved word in newer MoonBit — avoid it
  let local_secs = now_unix + tz_offset_minutes.to_int64() * 60L
  let mut days = local_secs / 86400L
  let mut secs = local_secs - days * 86400L
  if secs < 0L {
    days = days - 1L
    secs = secs + 86400L
  }
  let (y, m, d) = civil_from_days(days)
  let hh = (secs / 3600L).to_int()
  let mi = (secs % 3600L / 60L).to_int()
  let ss = (secs % 60L).to_int()
  let dow = week_days[((days % 7L + 7L + 4L) % 7L).to_int()]
  let az = if tz_offset_minutes < 0 {
    -tz_offset_minutes
  } else {
    tz_offset_minutes
  }
  let sign = if tz_offset_minutes < 0 { "-" } else { "+" }
  "\{dow}, \{pad2(d)} \{month_names[m - 1]} \{y} \{pad2(hh)}:\{pad2(mi)}:\{pad2(ss)} \{sign}\{pad2(az / 60)}\{pad2(az % 60)}"
}

///|
/// "<hex-random@domain>" per RFC 5322 §3.6.4; the domain must be a
/// non-empty dot-atom (alnum, dot, dash).
pub fn message_id(random16 : Bytes, domain : String) -> String raise {
  require_ascii(domain, "domain")
  guard domain != "" else {
    raise @error.PgpError::PgpError(msg="mail: empty domain")
  }
  for c in domain {
    let v = c.to_int()
    let ok = (v >= 0x41 && v <= 0x5A) ||
      (v >= 0x61 && v <= 0x7A) ||
      (v >= 0x30 && v <= 0x39) ||
      c == '.' ||
      c == '-'
    guard ok else {
      raise @error.PgpError::PgpError(msg="mail: invalid domain '\{domain}'")
    }
  }
  "<\{@primitives.to_hex(random16)}@\{domain}>"
}

///|
pub extend MailAddress with @moonbitlang/core/debug.Debug::{to_repr}
