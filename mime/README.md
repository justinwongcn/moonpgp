# mime — PGP/MIME composition, verification and delivery

`decrypt_mime` walks the decrypted MIME tree, verifies signatures and
delivers body text and attachments through `MimeCallbacks`.

## Delivery semantics (what the consumer receives)

- **Body text covered by a root `multipart/signed`**: the canonicalized
  form the signature was verified over — trailing transport whitespace
  stripped per line, CRLF line endings, exactly one final CRLF.
  Verification face = delivery face.
- **Body text without a signature covering it** (plain encrypted mail,
  unsigned parts): the raw bytes as transmitted.
- **Attachments (binary parts)**: always byte-exact. Line-based
  canonicalization would corrupt them.

## The line-ending residual on binary attachments — why it stays

An attacker who appends trailing whitespace to a line inside a signed
text part gets the verification to pass while the recipient would see
different bytes if the raw wire form were delivered. For text parts we
close that by delivering the canonicalized form. For binary parts the
residual — "verifies Ok, delivered as transmitted" — remains open in
this library **and in every PGP/MIME implementation we know of**
(Thunderbird/Enigmail, gopenpgp, GPGTools). It is a structural property
of RFC 1847/3156, not a defect specific to this codebase. Two facts
make it a non-issue in practice:

1. **Base64 transport neutralizes it.** PGP/MIME attachments travel
   7bit/base64 (RFC 3156 §3; our builder emits exactly that). A
   whitespace-only edit inside a base64 body passes text-mode
   canonicalization, is delivered with the whitespace — and the base64
   decoder ignores it, so the attachment bytes the consumer receives
   are identical to what was signed. The gap exists only at the raw
   wire-byte level, which no consumer reads.
2. **The 8bit escape hatch is unused.** The residual would need the
   attachment part transported as raw 8bit text — outside standard
   PGP/MIME practice, and binary signature types (0x00, no
   canonicalization) exist in OpenPGP precisely for such parts: with a
   binary-mode signature, line-ending tampering breaks verification.

Deliberately **not** built: a raw+canonical dual-delivery callback API.
It would complicate every consumer to guard against an attack that the
transport encoding already neutralizes — same verdict as the rest of
the industry.

## Non-MIME payloads

`decrypt_mime` also accepts bare armored messages. A decrypted payload
whose header block carries no `Content-Type` is raw content, not a MIME
tree, and is delivered as `text/plain` (matching gopenpgp's treatment
of non-MIME plaintext) instead of being parsed as headers.
