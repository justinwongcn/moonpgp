// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "justinwongcn/moonpgp"

version = "0.2.0"

readme = "README.mbt.md"

repository = "https://github.com/justinwongcn/moonpgp"

license = "Apache-2.0"

keywords = [
  "openpgp",
  "pgp",
  "encryption",
  "signature",
  "email",
  "crypto",
  "imap",
  "smtp",
  "mime",
]

preferred_target = "native"

description = "Pure-MoonBit OpenPGP implementation (RFC 4880/9580): email encryption, decryption, signing and verification, interoperable with GnuPG and gopenpgp."

import {
  "moonbitlang/x@0.5.5",
  "moonbit-community/flate@0.9.0",
  "moonbitlang/async@0.22.4",
}
