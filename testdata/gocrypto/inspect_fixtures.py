#!/usr/bin/env python3
"""Raw OpenPGP structure dumper for the go-crypto interop fixtures.

This is deliberately independent of go-crypto and of GNUnet/GnuPG: it decodes
the ASCII armor, walks the packet framing (old and new format, including
partial body lengths) and reports the fields this task cares about -- packet
versions, public-key/symmetric/AEAD algorithms, secret-key protection state,
S2K specifiers and parameters.

GnuPG 2.4.5 cannot parse v6 packets and rejects Argon2 S2K (type 4), so
`gpg --list-packets` is only usable on the two v4 fixtures. This script is the
fallback for the other four.

It does not decrypt anything, so it cannot show the plaintext; use the Go
verifier (verify/) for that.

Usage:
    python3 inspect_fixtures.py FILE [FILE ...]
    python3 inspect_fixtures.py --json FILE [FILE ...]
"""

import base64
import json
import sys

# ---------------------------------------------------------------- constants --

CIPHER_NAMES = {
    0: "Plaintext",
    1: "IDEA",
    2: "3DES",
    3: "CAST5",
    4: "Blowfish",
    7: "AES128",
    8: "AES192",
    9: "AES256",
    10: "Twofish",
    11: "Camellia128",
    12: "Camellia192",
    13: "Camellia256",
}

CIPHER_BLOCK = {
    1: 8, 2: 8, 3: 8, 4: 8, 7: 16, 8: 16, 9: 16, 10: 16, 11: 16, 12: 16, 13: 16
}

AEAD_NAMES = {1: "EAX", 2: "OCB", 3: "GCM"}
AEAD_IVLEN = {1: 16, 2: 15, 3: 12}
AEAD_TAGLEN = {1: 16, 2: 16, 3: 16}

PKALGO_NAMES = {
    1: "RSA", 2: "RSA-Encrypt-Only", 3: "RSA-Sign-Only",
    16: "ElGamal", 17: "DSA", 18: "ECDH", 19: "ECDSA", 22: "EdDSA-legacy",
    25: "X25519", 27: "Ed25519", 26: "X448", 28: "Ed448",
}

HASH_NAMES = {1: "MD5", 2: "SHA1", 3: "RIPEMD160", 8: "SHA256", 9: "SHA384",
              10: "SHA512", 11: "SHA224", 12: "SHA3-256", 14: "SHA3-512"}

SIGTYPE_NAMES = {
    0x00: "binary", 0x01: "text", 0x02: "standalone", 0x10: "generic-cert",
    0x11: "persona-cert", 0x12: "casual-cert", 0x13: "positive-cert",
    0x18: "subkey-binding", 0x19: "primary-key-binding", 0x1F: "direct-key",
    0x20: "key-revocation", 0x28: "subkey-revocation", 0x30: "cert-revocation",
    0x40: "timestamp", 0x50: "third-party-confirmation",
}

TAG_NAMES = {
    1: "PKESK", 2: "Signature", 3: "SKESK", 4: "One-Pass-Sig", 5: "SecretKey",
    6: "PublicKey", 7: "SecretSubkey", 8: "CompressedData", 9: "SED",
    11: "LiteralData", 13: "UserID", 14: "PublicSubkey",
    17: "UserAttribute", 18: "SEIPD",
}


def cipher_name(c):
    return CIPHER_NAMES.get(c, "unknown(%d)" % c)


def aead_name(m):
    return AEAD_NAMES.get(m, "unknown(%d)" % m)


def hash_name(h):
    return HASH_NAMES.get(h, "unknown(%d)" % h)


def pk_name(a):
    return PKALGO_NAMES.get(a, "unknown(%d)" % a)


# ------------------------------------------------------------ armor + packet --

def dearmor(data):
    if b"-----BEGIN PGP" not in data:
        return data, None
    text = data.decode("ascii", "replace")
    lines = text.splitlines()
    btype = None
    b64 = []
    inside = False
    for line in lines:
        if line.startswith("-----BEGIN PGP"):
            btype = line.strip("-").replace("BEGIN ", "").strip()
            inside = True
            continue
        if line.startswith("-----END PGP"):
            inside = False
            continue
        if inside:
            if not line or ":" in line and not line[0].isalnum():
                continue
            if line.startswith("="):  # CRC
                continue
            b64.append(line.strip())
    return base64.b64decode("".join(b64)), btype


def read_new_length(data, pos):
    """Returns (length_or_None, partial_power_or_None, newpos)."""
    o1 = data[pos]
    pos += 1
    if o1 < 192:
        return o1, None, pos
    if o1 < 224:
        o2 = data[pos]
        pos += 1
        return ((o1 - 192) << 8) + o2 + 192, None, pos
    if o1 == 255:
        n = int.from_bytes(data[pos:pos + 4], "big")
        return n, None, pos + 4
    return None, o1 & 0x1F, pos


def parse_packets(data):
    packets = []
    pos = 0
    n = len(data)
    while pos < n:
        hdr = data[pos]
        if not (hdr & 0x80):
            raise ValueError("not a packet header at offset %d: %02x" % (pos, hdr))
        pos += 1
        if hdr & 0x40:  # new format
            tag = hdr & 0x3F
            body = b""
            while True:
                length, partial, pos = read_new_length(data, pos)
                if partial is None:
                    body += data[pos:pos + length]
                    pos += length
                    break
                chunk = 1 << partial
                body += data[pos:pos + chunk]
                pos += chunk
            packets.append((tag, body))
        else:  # old format
            tag = (hdr >> 2) & 0x0F
            lt = hdr & 0x03
            if lt == 0:
                length = data[pos]
                pos += 1
            elif lt == 1:
                length = int.from_bytes(data[pos:pos + 2], "big")
                pos += 2
            elif lt == 2:
                length = int.from_bytes(data[pos:pos + 4], "big")
                pos += 4
            else:
                length = n - pos
            packets.append((tag, data[pos:pos + length]))
            pos += length
    return packets


# ------------------------------------------------------------------- fields --

def read_mpi(data, pos):
    bits = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    nbytes = (bits + 7) // 8
    return bits, pos + nbytes


def skip_public_material(data, pos, algo):
    """Skip a v4 public-key material blob, returning the new offset."""
    if algo in (1, 2, 3):  # RSA: n, e
        _, pos = read_mpi(data, pos)
        _, pos = read_mpi(data, pos)
    elif algo in (16,):  # ElGamal: p, g, y
        for _ in range(3):
            _, pos = read_mpi(data, pos)
    elif algo in (17,):  # DSA: p, q, g, y
        for _ in range(4):
            _, pos = read_mpi(data, pos)
    elif algo in (18,):  # ECDH: OID, point, KDF params
        oidlen = data[pos]
        pos += 1 + oidlen
        _, pos = read_mpi(data, pos)
        kdflen = data[pos]
        pos += 1 + kdflen
    elif algo in (19, 22):  # ECDSA / EdDSA: OID, point
        oidlen = data[pos]
        pos += 1 + oidlen
        _, pos = read_mpi(data, pos)
    elif algo in (25, 26, 27, 28):  # X25519/X448/Ed25519/Ed448: one MPI
        _, pos = read_mpi(data, pos)
    else:
        raise ValueError("cannot skip public key material for algo %d" % algo)
    return pos


def parse_s2k(data, pos):
    stype = data[pos]
    pos += 1
    out = {"type": stype}
    if stype == 0:
        out["hash"] = hash_name(data[pos]); pos += 1
    elif stype == 1:
        out["hash"] = hash_name(data[pos]); pos += 1
        out["salt"] = data[pos:pos + 8].hex(); pos += 8
    elif stype == 3:
        out["hash"] = hash_name(data[pos]); pos += 1
        out["salt"] = data[pos:pos + 8].hex(); pos += 8
        c = data[pos]; pos += 1
        out["count_octet"] = c
        if c < 16:
            out["count"] = (16 + (c & 15)) << ((c >> 4) + 6)
        else:
            out["count"] = (16 + (c & 15)) << ((c >> 4) + 6)  # same formula
        out["kdf"] = "iterated-salted"
    elif stype == 4:
        out["kdf"] = "argon2"
        out["salt"] = data[pos:pos + 16].hex(); pos += 16
        out["argon2_t"] = data[pos]; pos += 1
        out["argon2_p"] = data[pos]; pos += 1
        m = data[pos]; pos += 1
        out["argon2_encoded_m"] = m
        out["argon2_m_kib"] = 1 << m
    elif 100 <= stype <= 110:
        out["kdf"] = "private/experimental(%d)" % stype
        out["hash"] = hash_name(data[pos]); pos += 1
        out["salt"] = data[pos:pos + 8].hex(); pos += 8
    else:
        raise ValueError("unknown S2K type %d" % stype)
    return out, pos


def parse_secret_key(data):
    ver = data[0]
    out = {"version": ver}
    if ver in (2, 3):
        raise ValueError("v2/v3 secret keys are out of scope")
    pos = 1
    out["created"] = int.from_bytes(data[pos:pos + 4], "big"); pos += 4
    algo = data[pos]; pos += 1
    out["algo"] = pk_name(algo)
    if ver == 4:
        bits, _ = read_mpi(data, pos)
        if algo in (1, 2, 3):
            out["rsa_bits"] = bits
        pos = skip_public_material(data, pos, algo)
    elif ver == 5:
        raise ValueError("v5 secret keys are out of scope")
    elif ver == 6:
        mlen = int.from_bytes(data[pos:pos + 4], "big"); pos += 4
        if algo in (1, 2, 3):
            bits, _ = read_mpi(data, pos)
            out["rsa_bits"] = bits
        pos += mlen
    else:
        raise ValueError("unknown secret key version %d" % ver)

    usage = data[pos]; pos += 1
    out["s2k_usage"] = usage
    if usage == 0:
        out["protection"] = "unprotected"
        out["remaining_private_bytes"] = len(data) - pos
        return out

    out["protection"] = ("AEAD (253)" if usage == 253
                         else "SHA1-checksum (%d)" % usage)
    # RFC 9580: a version 6 protected secret key adds a one-octet "count of
    # the following field" both before the cipher octet and before the S2K
    # specifier. go-crypto's PrivateKey.parse reads exactly those two.
    if ver == 6:
        out["count_before_cipher"] = data[pos]; pos += 1
    cipher = data[pos]; pos += 1
    out["cipher"] = cipher_name(cipher)
    if usage == 253:
        mode = data[pos]; pos += 1
        out["aead_mode"] = aead_name(mode)
    if ver == 6:
        out["count_before_s2k"] = data[pos]; pos += 1
    s2k, pos = parse_s2k(data, pos)
    out["s2k"] = s2k
    if usage == 253:
        ivlen = AEAD_IVLEN.get(mode, 15)
    else:
        ivlen = CIPHER_BLOCK.get(cipher, 16)
    pos += ivlen
    out["encrypted_private_bytes"] = len(data) - pos
    return out


def parse_public_key(data):
    ver = data[0]
    out = {"version": ver}
    pos = 1
    out["created"] = int.from_bytes(data[pos:pos + 4], "big"); pos += 4
    algo = data[pos]; pos += 1
    out["algo"] = pk_name(algo)
    return out


def parse_pkesk(data):
    ver = data[0]
    out = {"version": ver}
    pos = 1
    if ver == 3:
        out["keyid"] = data[pos:pos + 8].hex(); pos += 8
        out["algo"] = pk_name(data[pos]); pos += 1
    elif ver == 6:
        size = data[pos]; pos += 1
        if size:
            out["key_version"] = data[pos]; pos += 1
            fp_len = 32 if out["key_version"] == 6 else 20
            pos += fp_len
        out["algo"] = pk_name(data[pos]); pos += 1
    else:
        raise ValueError("unknown PKESK version %d" % ver)
    out["encrypted_key_bytes"] = len(data) - pos
    return out


def parse_skesk(data):
    ver = data[0]
    out = {"version": ver}
    pos = 1
    if ver > 5:
        out["scalar_count_1"] = data[pos]; pos += 1
    cipher = data[pos]; pos += 1
    out["cipher"] = cipher_name(cipher)
    if ver >= 5:
        mode = data[pos]; pos += 1
        out["aead_mode"] = aead_name(mode)
    if ver > 5:
        out["s2k_len"] = data[pos]; pos += 1
    s2k, pos = parse_s2k(data, pos)
    out["s2k"] = s2k
    if ver >= 5:
        pos += AEAD_IVLEN.get(mode, 15)
        out["encrypted_session_key_bytes"] = len(data) - pos
    else:
        out["encrypted_session_key_bytes"] = len(data) - pos
    return out


def parse_seipd(data):
    ver = data[0]
    out = {"version": ver}
    if ver == 1:
        out["mode"] = "OpenPGP-CFB + MDC"
        out["payload_bytes"] = len(data) - 1
    elif ver == 2:
        out["cipher"] = cipher_name(data[1])
        out["aead_mode"] = aead_name(data[2])
        out["chunk_size_octet"] = data[3]
        out["chunk_size"] = 1 << (data[3] + 6)
        out["salt"] = data[4:36].hex()
        out["payload_bytes"] = len(data) - 36
    else:
        raise ValueError("unknown SEIPD version %d" % ver)
    return out


def parse_subpackets(data):
    subs = []
    pos = 0
    while pos < len(data):
        o1 = data[pos]
        if o1 == 0:
            subs.append({"len": 0, "note": "padding"})
            pos += 1
            continue
        pos += 1
        if o1 < 192:
            length = o1
        elif o1 < 255:
            length = ((o1 - 192) << 8) + data[pos] + 192
            pos += 1
        else:
            length = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
        raw_type = data[pos]
        critical = bool(raw_type & 0x80)
        stype = raw_type & 0x7F
        body = data[pos + 1:pos + length]
        pos += length  # 'length' counts the type octet too
        prefix = {"type": stype}
        if critical:
            prefix["critical"] = True
        if stype == 20:  # notation: flags(4), namelen(2), valuelen(2), name, value
            name_len = int.from_bytes(body[4:6], "big")
            value_len = int.from_bytes(body[6:8], "big")
            name = body[8:8 + name_len].decode("utf-8", "replace")
            value = body[8 + name_len:8 + name_len + value_len]
            subs.append({**prefix, "notation": name, "value_len": value_len,
                         "human_readable": bool(body[0] & 0x80)})
        elif stype == 39:
            suites = []
            for i in range(0, len(body) - 1, 2):
                suites.append([cipher_name(body[i]), aead_name(body[i + 1])])
            subs.append({**prefix, "preferred_aead": suites})
        elif stype == 30:
            subs.append({**prefix, "features": body.hex()})
        elif stype == 27:
            subs.append({**prefix, "key_flags": body.hex()})
        elif stype == 33:
            subs.append({**prefix, "issuer_fpr": body.hex()})
        elif stype == 2:
            subs.append({**prefix, "created": int.from_bytes(body[:4], "big")})
        elif stype in (11, 21, 22):
            subs.append({**prefix, "values": list(body)})
        elif stype == 25:
            subs.append({**prefix, "primary_uid": body.hex()})
        else:
            subs.append({**prefix, "len": len(body)})
    return subs


def parse_signature(data):
    ver = data[0]
    out = {"version": ver}
    sigtype = data[1]
    out["sig_type"] = SIGTYPE_NAMES.get(sigtype, "unknown(0x%02x)" % sigtype)
    out["algo"] = pk_name(data[2])
    out["hash"] = hash_name(data[3])
    if ver == 6:
        hlen = int.from_bytes(data[4:8], "big")
        pos = 8
    else:
        hlen = int.from_bytes(data[4:6], "big")
        pos = 6
    hashed = data[pos:pos + hlen]
    pos += hlen
    out["hashed_subpackets"] = parse_subpackets(hashed)
    if ver == 6:
        ulen = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4 + ulen
    else:
        ulen = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + ulen
    out["unhashed_bytes"] = ulen
    return out


def describe(tag, body):
    if tag in (5, 7):
        return {"packet": TAG_NAMES[tag], **parse_secret_key(body)}
    if tag in (6, 14):
        return {"packet": TAG_NAMES[tag], **parse_public_key(body)}
    if tag == 1:
        return {"packet": "PKESK", **parse_pkesk(body)}
    if tag == 3:
        return {"packet": "SKESK", **parse_skesk(body)}
    if tag == 18:
        return {"packet": "SEIPD", **parse_seipd(body)}
    if tag == 2:
        return {"packet": "Signature", **parse_signature(body)}
    if tag == 13:
        return {"packet": "UserID", "user_id": body.decode("utf-8", "replace")}
    return {"packet": TAG_NAMES.get(tag, "tag-%d" % tag), "bytes": len(body)}


def summarize(path, canonical=False):
    with open(path, "rb") as fh:
        raw = fh.read()
    data, btype = dearmor(raw)
    packets = [describe(t, b) for t, b in parse_packets(data)]
    report = {"file": path.split("/")[-1], "armor": btype, "packets": packets}
    if canonical:
        report = mask_random(report)
    return report


# Fields that legitimately differ between two generator runs (random key
# material, random salts, key fingerprints, creation timestamps). Masking them
# lets two structurally identical files compare equal.
RANDOM_FIELDS = {"salt", "issuer_fpr", "created"}


def mask_random(value):
    if isinstance(value, dict):
        return {
            k: ("<random>" if k in RANDOM_FIELDS else mask_random(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [mask_random(v) for v in value]
    return value


def main():
    args = sys.argv[1:]
    as_json = False
    canonical = False
    while args and args[0].startswith("--"):
        if args[0] == "--json":
            as_json = True
        elif args[0] == "--canonical":
            canonical = True
        else:
            raise SystemExit("unknown flag %s" % args[0])
        args = args[1:]
    reports = [summarize(p, canonical) for p in args]
    if as_json:
        print(json.dumps(reports, indent=2, sort_keys=True))
        return
    for r in reports:
        print("=== %s (armor: %s)" % (r["file"], r["armor"]))
        for p in r["packets"]:
            print("  " + json.dumps(p, sort_keys=True))
        print()


if __name__ == "__main__":
    main()
