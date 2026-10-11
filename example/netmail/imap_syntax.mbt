///|
/// One segment of a logical response line: inline syntax text, or the
/// raw bytes of an inline literal.
priv enum Seg {
  Txt(Bytes)
  Lit(Bytes)
}

///|
/// Parsed response tokens. `Atom` covers numbers, keywords and
/// bracketed sections; `Raw` is a literal delivered at this position.
priv enum Node {
  Atom(String)
  Quoted(String)
  Parens(Array[Node])
  Raw(Bytes)
}

///|
/// Read one logical response line: a raw line, plus (while the text
/// tail ends with a `{n}` / `{n+}` marker) the exact literal and the
/// continuation text. The marker itself is framing and is stripped
/// from the text segment, exactly like the CRLF.
fn read_logical_line(sock : &Socket) -> Array[Seg] raise {
  let segs : Array[Seg] = []
  while true {
    let raw = sock.read_raw_line()
    let size = literal_marker_size(raw)
    if size >= 0 {
      let cut = marker_cut_index(raw)
      segs.push(Seg::Txt(raw[0:cut].to_owned()))
      segs.push(Seg::Lit(sock.read_exact(size)))
      continue
    }
    segs.push(Seg::Txt(raw))
    return segs
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
/// Literal size when the line ends with `{n}` or `{n+}`, else -1.
fn literal_marker_size(b : Bytes) -> Int raise {
  let n = b.length()
  guard n >= 3 else { return -1 }
  guard b[n - 1] == b'}' else { return -1 }
  let mut k = n - 2
  // optional LITERAL+ suffix: {5+}
  if b[k] == b'+' {
    k = k - 1
  }
  let digits_end = k
  while k >= 1 && b[k] >= b'0' && b[k] <= b'9' {
    k = k - 1
  }
  guard k >= 0 && b[k] == b'{' && digits_end > k else { return -1 }
  // sanity: a syntax-text `{digits}` is only ever server framing; a
  // huge value means we misread the stream — refuse instead of trying
  // to read_exact it. The accumulation is overflow-checked: a 2^32+k
  // digit string wraps to a small Int and would sneak past a plain
  // post-hoc bound (review finding m1).
  let max_literal = 100_000_000
  let start = k + 1
  let stop = digits_end + 1
  let mut v = 0
  for i in start..<stop {
    let d = b[i].to_int() - 48
    if v > (max_literal - d) / 10 {
      @error.fail("mailreader: implausible literal size (overflow guard)")
    }
    v = v * 10 + d
  }
  v
}

///|
/// Index of the `{` opening the trailing literal marker.
fn marker_cut_index(b : Bytes) -> Int {
  let n = b.length()
  let mut k = n - 2
  if b[k] == b'+' {
    k = k - 1
  }
  while k >= 1 && b[k] >= b'0' && b[k] <= b'9' {
    k = k - 1
  }
  k
}

///|
/// Quote/paren-aware scanner: Segs → top-level Nodes. `[...]` sections
/// bind to the current atom and swallow their whole content (no nested
/// sections exist in the subset), quoted strings honor `\\` escapes,
/// and a Lit segment becomes a Raw node at its position.
fn parse_nodes(segs : Array[Seg]) -> Array[Node] raise {
  let out : Array[Node] = []
  let mut si = 0
  let mut bi = 0
  while si < segs.length() {
    match segs[si] {
      Lit(data) => {
        out.push(Node::Raw(data))
        si = si + 1
        bi = 0
      }
      Txt(text) => {
        if bi >= text.length() {
          si = si + 1
          bi = 0
          continue
        }
        let c = text[bi]
        if c == b' ' {
          bi = bi + 1
          continue
        }
        if c == b'"' {
          let (q, nbi) = scan_quoted(text, bi + 1)
          out.push(Node::Quoted(q))
          bi = nbi
          continue
        }
        if c == b'(' {
          let (items, ni, nbi) = scan_parens(segs, si, bi + 1)
          out.push(Node::Parens(items))
          si = ni
          bi = nbi
          continue
        }
        let (atom, ni, nbi) = scan_atom(segs, si, bi)
        out.push(Node::Atom(atom))
        si = ni
        bi = nbi
      }
    }
  }
  out
}

///|
fn scan_quoted(text : Bytes, start : Int) -> (String, Int) raise {
  let sb = StringBuilder()
  let mut i = start
  while i < text.length() {
    let c = text[i]
    if c == b'\\' && i + 1 < text.length() {
      sb.write_char(byte_to_char(text[i + 1]))
      i = i + 2
      continue
    }
    if c == b'"' {
      return (sb.to_string(), i + 1)
    }
    sb.write_char(byte_to_char(c))
    i = i + 1
  }
  @error.fail("mailreader: unterminated quoted string")
}

///|
fn scan_parens(
  segs : Array[Seg],
  si : Int,
  bi : Int,
) -> (Array[Node], Int, Int) raise {
  let items : Array[Node] = []
  let mut s = si
  let mut b = bi
  while true {
    guard s < segs.length() else {
      @error.fail("mailreader: unterminated list")
    }
    match segs[s] {
      Lit(data) => {
        items.push(Node::Raw(data))
        s = s + 1
        b = 0
      }
      Txt(text) => {
        if b >= text.length() {
          s = s + 1
          b = 0
          continue
        }
        let c = text[b]
        if c == b' ' {
          b = b + 1
          continue
        }
        if c == b')' {
          return (items, s, b + 1)
        }
        if c == b'(' {
          let (inner, ns, nb) = scan_parens(segs, s, b + 1)
          items.push(Node::Parens(inner))
          s = ns
          b = nb
          continue
        }
        if c == b'"' {
          let (q, nb) = scan_quoted(text, b + 1)
          items.push(Node::Quoted(q))
          b = nb
          continue
        }
        let (atom, ns, nb) = scan_atom(segs, s, b)
        items.push(Node::Atom(atom))
        s = ns
        b = nb
      }
    }
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
/// One atom: runs of non-space/non-delim bytes; a `[` section binds to
/// the atom and consumes through the matching `]` (spaces and parens
/// inside a section are part of it).
fn scan_atom(segs : Array[Seg], si : Int, bi : Int) -> (String, Int, Int) raise {
  let sb = StringBuilder()
  let mut s = si
  let mut b = bi
  while true {
    guard s < segs.length() else { return (sb.to_string(), s, b) }
    match segs[s] {
      Lit(_) =>
        // a literal directly after an atom terminates the atom
        return (sb.to_string(), s, b)
      Txt(text) => {
        if b >= text.length() {
          s = s + 1
          b = 0
          continue
        }
        let c = text[b]
        if c == b' ' || c == b'(' || c == b')' || c == b'"' {
          return (sb.to_string(), s, b)
        }
        if c == b'[' {
          // section: swallow through the matching ']'
          sb.write_char('[')
          b = b + 1
          let mut depth = 1
          let mut closed = false
          while s < segs.length() && !closed {
            match segs[s] {
              Lit(_) =>
                // sections never contain literals; treat as end
                break
              Txt(t) => {
                while b < t.length() {
                  let d = t[b]
                  b = b + 1
                  sb.write_char(byte_to_char(d))
                  if d == b']' {
                    depth = depth - 1
                    if depth == 0 {
                      closed = true
                      break
                    }
                  }
                }
                if !closed {
                  s = s + 1
                  b = 0
                }
              }
            }
          }
          guard closed else {
            @error.fail("mailreader: unterminated section atom")
          }
          continue
        }
        sb.write_char(byte_to_char(c))
        b = b + 1
      }
    }
  } nobreak {
    // Unreachable: every exit is a return/raise. The nobreak arm satisfies
    // the typechecker, which does not treat `while true` as diverging
    // (E4108, HANDOFF 2026-10-06).
    abort("mailreader: unreachable")
  }
}

///|
fn node_text(node : Node) -> String {
  match node {
    Atom(s) => s
    Quoted(s) => "\{s}"
    Parens(items) => {
      let parts : Array[String] = []
      for it in items {
        parts.push(node_text(it))
      }
      "(\{parts.join(" ")})"
    }
    Raw(data) => bytes_lossy(data)
  }
}

///|
pub fn bytes_lossy(data : Bytes) -> String {
  let sb = StringBuilder()
  for b in data {
    match b.to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => sb.write_char('?')
    }
  }
  sb.to_string()
}

///|
/// Lossy char helper shared by the scanners: invalid scalars become '?'.
fn byte_to_char(b : Byte) -> Char {
  match b.to_int().to_char() {
    Some(c) => c
    None => '?'
  }
}
