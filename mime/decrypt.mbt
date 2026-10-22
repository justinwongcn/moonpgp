///|
/// Callbacks for decrypt_mime, mirroring gopenpgp's MIMECallbacks.
/// `on_body` receives the sanitized (lossy UTF-8) body text; attachments
/// deliver raw bytes. The methods cannot propagate errors (v1 decision).
pub(open) trait MimeCallbacks {
  fn on_body(Self, body : String, mimetype : String) -> Unit
  fn on_attachment(Self, headers : Array[(String, String)], data : Bytes) -> Unit
  fn on_verified(Self, status : @api.VerifyStatus) -> Unit
  fn on_error(Self, message : String) -> Unit
}

///|
/// Severity ranking for merging signature statuses (gopenpgp
/// prioritizeSignatureErrors: FAILED > NO_VERIFIER > NOT_SIGNED > OK).
fn severity(status : @api.VerifyStatus) -> Int32 {
  match status {
    @api.NotSigned => 1
    @api.NoVerifier => 2
    @api.Failed => 3
    @api.Ok => 0
  }
}

///|
/// Result ranking across candidate verifiers: a verified signature beats
/// any failure; among failures the severity order applies.
fn rank(status : @api.VerifyStatus) -> Int32 {
  match status {
    @api.Ok => 4
    other => severity(other)
  }
}

///|
fn status_worse(
  a : @api.VerifyStatus,
  b : @api.VerifyStatus,
) -> @api.VerifyStatus {
  if severity(a) >= severity(b) {
    a
  } else {
    b
  }
}

///|
fn status_message(status : @api.VerifyStatus) -> String {
  match status {
    @api.NotSigned => "mime: missing signature"
    @api.NoVerifier => "mime: no matching signature"
    @api.Failed => "mime: invalid signature"
    @api.Ok => "mime: signature ok"
  }
}

///|
/// PGP-layer outcome: the decrypted payload plus the embedded signature
/// status (None when no verification was attempted).
priv struct DecryptOutcome {
  data : Bytes
  embedded : @api.VerifyStatus?
}

///|
/// Decrypt the PGP layer. With keys and verifiers, tries each verifier
/// and keeps the best rank among successful decryptions. Falls back to
/// the password path whenever the key paths fail (a message may be
/// password-encrypted even though keys were supplied). Raises with the
/// last underlying error when everything fails.
fn decrypt_payload(
  armored_message : String,
  keys : Array[@api.PrivateKey],
  password : String?,
  verifiers : Array[@api.PublicKey],
) -> DecryptOutcome raise {
  let mut last_error : String? = None
  if !keys.is_empty() {
    if !verifiers.is_empty() {
      let mut best : DecryptOutcome? = None
      for v in verifiers {
        let outcome : DecryptOutcome? = try {
          let (d, s) = @api.decrypt_and_verify(armored_message, keys, Some(v))
          let take = match best {
            None => true
            Some(cur) =>
              match cur.embedded {
                Some(cs) => rank(s) > rank(cs)
                None => true
              }
          }
          if take {
            Some(DecryptOutcome::{ data: d, embedded: Some(s), })
          } else {
            None
          }
        } catch {
          e => {
            last_error = Some("\{e}")
            None
          }
        }
        if outcome is Some(o) {
          best = Some(o)
        }
      }
      if best is Some(o) {
        return o
      }
    } else {
      let outcome : DecryptOutcome? = try {
        let (d, _s) = @api.decrypt_and_verify(armored_message, keys, None)
        Some(DecryptOutcome::{ data: d, embedded: None, })
      } catch {
        e => {
          last_error = Some("\{e}")
          None
        }
      }
      if outcome is Some(o) {
        return o
      }
    }
  }
  match password {
    Some(p) => {
      let outcome : DecryptOutcome? = try {
        let d = @api.decrypt_with_password(armored_message, p)
        Some(DecryptOutcome::{ data: d, embedded: None, })
      } catch {
        e => {
          last_error = Some("\{e}")
          None
        }
      }
      if outcome is Some(o) {
        return o
      }
    }
    None => ()
  }
  match last_error {
    Some(e) => @error.fail("mime: decryption failed: \{e}")
    None => @error.fail("mime: no decryption material")
  }
}

///|
priv enum MimeSignedOutcome {
  Status(@api.VerifyStatus)
  Fatal(String)
}

///|
/// Verify the signature of a multipart/signed over the raw signed part
/// (headers + body, canonicalized per RFC 3156 §5 conventions).
fn verify_inner_signed(
  signed_part : MimePart,
  sig_part : MimePart,
  verifiers : Array[@api.PublicKey],
) -> MimeSignedOutcome {
  let canonical = mime_canonicalize(signed_part.raw.exact_view())
  let sig_cte = sig_part.header("Content-Transfer-Encoding")
  let sig_bytes : Bytes = decode_transfer_encoding(
    sig_part.body_raw.exact_view(),
    sig_cte,
  ) catch {
    e =>
      return MimeSignedOutcome::Fatal("mime: signature part unreadable: \{e}")
  }
  if verifiers.is_empty() {
    // gopenpgp's nil verify handle behaves as "no matching signature".
    return MimeSignedOutcome::Status(@api.NoVerifier)
  }
  let sig_armor = @utf8.decode_lossy(sig_bytes.exact_view())
  let mut best = @api.NoVerifier
  for v in verifiers {
    let outcome : @api.VerifyStatus = @api.verify_detached(
      canonical.exact_view(),
      sig_armor,
      v,
    ) catch {
      e =>
        return MimeSignedOutcome::Fatal(
          "mime: signature verification error: \{e}",
        )
    }
    if outcome is @api.Ok {
      return MimeSignedOutcome::Status(@api.Ok)
    }
    best = status_worse(outcome, best)
  }
  MimeSignedOutcome::Status(best)
}

///|
/// Canonicalize the signed entity of a multipart/signed (RFC 3156 §5):
/// trim trailing spaces/tabs per line, re-join with CRLF, and end with
/// exactly one CRLF (the one preceding the boundary belongs to the
/// signed data by OpenPGP convention). This covers both the GnuPG shape
/// (no extra blank line before the boundary) and the Proton/gopenpgp
/// builder shape (extra blank line). gopenpgp itself lacks the
/// conditional tail restore and fails on GnuPG-shaped input — a
/// deliberate deviation, empirically verified against gpg 2.4.5.
fn mime_canonicalize(data : BytesView) -> Bytes {
  let n = data.length()
  let out : Array[Byte] = []
  let mut pos = 0
  let mut any = false
  while pos < n {
    match next_line(data, pos) {
      None => break
      Some((cs, ce, np)) => {
        let mut end = ce
        while end > cs && (data[end - 1] == b' ' || data[end - 1] == b'\t') {
          end = end - 1
        }
        if any {
          out.push(b'\r')
          out.push(b'\n')
        }
        for k in cs..<end {
          out.push(data[k])
        }
        any = true
        pos = np
      }
    }
  }
  if any {
    out.push(b'\r')
    out.push(b'\n')
  }
  Bytes::from_array(out)
}

///|
/// Decrypt an armored PGP message whose payload is a MIME tree, walk the
/// tree, verify a root-level multipart/signed (RFC 1847/3156) and deliver
/// body + attachments through `callbacks`. Runtime failures (decryption,
/// malformed MIME) go to `on_error` — like gopenpgp's Decrypt this
/// function does not raise for them. Signature statuses merge per the
/// gopenpgp truth table: only when both the embedded and the MIME
/// verification fail are errors reported (plus the worse status);
/// otherwise a non-empty verifier list yields Ok. Password decryption
/// cannot check the embedded PGP-layer signature, so with verifiers
/// requested it counts as NotSigned (matching gopenpgp's !md.IsSigned).
/// With no verifiers, no verification is attempted and on_verified is
/// never called. Body and attachments are delivered regardless of the
/// signature outcome.
pub fn decrypt_mime(
  armored_message : String,
  decryption_keys : Array[@api.PrivateKey],
  verifiers~ : Array[@api.PublicKey],
  callbacks~ : &MimeCallbacks,
  password? : String,
) -> Unit {
  // 1. PGP layer.
  let outcome = decrypt_payload(
    armored_message, decryption_keys, password, verifiers,
  ) catch {
    e => {
      callbacks.on_error("mime: decryption failed: \{e}")
      return
    }
  }
  // 2. MIME tree over the raw decrypted bytes (sanitizing happens later,
  // on the delivered body only, so binary leaves stay intact).
  let root = parse_mime_tree(outcome.data) catch {
    e => {
      callbacks.on_error("mime: \{e}")
      return
    }
  }
  let root_signed = root.is_multipart() &&
    root.content_type.sub_type == "signed"
  // 3. MIME signature status (root multipart/signed only, as gopenpgp).
  // RFC 1847 requires exactly two parts; malformed signed roots are
  // passed along unverified instead of hard-failing (gopenpgp behavior).
  let verifiable = root_signed && root.parts.length() == 2
  let mut mime_status = @api.NotSigned
  if verifiable {
    match verify_inner_signed(root.parts[0], root.parts[1], verifiers) {
      MimeSignedOutcome::Status(s) => mime_status = s
      MimeSignedOutcome::Fatal(msg) => {
        callbacks.on_error(msg)
        return
      }
    }
  }
  // 4. Merge embedded + MIME statuses (gopenpgp mime.go Decrypt truth
  // table): errors surface only when both sides failed.
  let embedded : @api.VerifyStatus? = match outcome.embedded {
    Some(@api.Ok) => None
    Some(other) => Some(other)
    // No embedded check happened (password path): with verifiers requested
    // this still counts as an error side, like gopenpgp's NOT_SIGNED.
    None => if verifiers.is_empty() { None } else { Some(@api.NotSigned) }
  }
  let mime_err : @api.VerifyStatus? = match mime_status {
    @api.Ok => None
    other => Some(other)
  }
  match (embedded, mime_err) {
    (Some(e1), Some(e2)) => {
      callbacks.on_error(status_message(e1))
      callbacks.on_error(status_message(e2))
      callbacks.on_verified(status_worse(e1, e2))
    }
    _ => if !verifiers.is_empty() { callbacks.on_verified(@api.Ok) }
  }
  // 5. Deliver body and attachments regardless of the signature outcome.
  let collect_root = if verifiable { root.parts[0] } else { root }
  let (body, attachments) = collect_body_and_attachments(collect_root)
  match body {
    Some(b) =>
      callbacks.on_body(@utf8.decode_lossy(b.content.exact_view()), b.mimetype)
    None => callbacks.on_body("", "text/plain")
  }
  for att in attachments {
    callbacks.on_attachment(att.headers, att.data)
  }
}
