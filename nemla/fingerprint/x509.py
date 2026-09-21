"""A small, defensive X.509 reader (DER) for certificate inspection.

The standard library can only decode certificates through a private helper
that needs a file on disk. This module reads what Nemla needs directly from
the DER bytes instead: names, validity, signature algorithm, key type and size,
and the subject alternative names. Certificates come from servers we do not
trust, so every length is bounds-checked and anything odd raises X509Error.
"""
from __future__ import annotations

import calendar

MAX_DER = 256 * 1024
MAX_SAN = 50

_SIG_ALGS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
_CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384),
           "1.3.132.0.35": ("P-521", 521), "1.3.132.0.10": ("secp256k1", 256)}
_NAME_ATTRS = {"2.5.4.3": "commonName", "2.5.4.10": "organizationName",
               "2.5.4.11": "organizationalUnitName", "2.5.4.6": "countryName"}


class X509Error(ValueError):
    """The certificate is malformed (or not a certificate at all)."""


def _read(data: bytes, pos: int, end: int) -> tuple:
    """One DER element at `pos`: (tag, content_start, content_end)."""
    if pos + 2 > end:
        raise X509Error("truncated")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > end:
            raise X509Error("bad length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > end:
        raise X509Error("length past the end")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int):
    pos = start
    while pos < end:
        tag, cs, ce = _read(data, pos, end)
        yield tag, cs, ce
        pos = ce


def _expect(data: bytes, pos: int, end: int, tag: int) -> tuple:
    found, cs, ce = _read(data, pos, end)
    if found != tag:
        raise X509Error(f"expected tag {tag:#x}, found {found:#x}")
    return cs, ce


def _oid(data: bytes, start: int, end: int) -> str:
    if start >= end:
        raise X509Error("empty OID")
    first = data[start]
    parts, value = [first // 40, first % 40], 0
    for byte in data[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _text(tag: int, raw: bytes) -> str:
    try:
        if tag == 0x1E:
            return raw.decode("utf-16-be")
        if tag == 0x1C:
            return raw.decode("utf-32-be")
        return raw.decode("utf-8" if tag == 0x0C else "latin-1")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _time(tag: int, raw: bytes) -> int:
    text = raw.decode("ascii", "replace")
    try:
        if tag == 0x17 and len(text) >= 12:            # UTCTime YYMMDDHHMMSSZ
            year = int(text[:2])
            year += 1900 if year >= 50 else 2000
            rest = text[2:12]
        elif tag == 0x18 and len(text) >= 14:          # GeneralizedTime YYYYMMDDHHMMSSZ
            year, rest = int(text[:4]), text[4:14]
        else:
            raise X509Error("bad time")
        month, day, hour, minute, second = (int(rest[i:i + 2]) for i in range(0, 10, 2))
        return calendar.timegm((year, month, day, hour, minute, second))
    except (ValueError, OverflowError):
        raise X509Error("bad time") from None


def _name(data: bytes, start: int, end: int) -> dict:
    """{attribute: first value} of a distinguished name."""
    out = {}
    for tag, cs, ce in _children(data, start, end):           # RDN (SET)
        if tag != 0x31:
            raise X509Error("bad name")
        for atag, acs, ace in _children(data, cs, ce):          # AttributeTypeAndValue
            if atag != 0x30:
                raise X509Error("bad name")
            otag, ocs, oce = _read(data, acs, ace)
            vtag, vcs, vce = _read(data, oce, ace)
            key = _NAME_ATTRS.get(_oid(data, ocs, oce)) if otag == 0x06 else None
            if key and key not in out:
                out[key] = _text(vtag, data[vcs:vce])
    return out


def _key_info(data: bytes, start: int, end: int) -> tuple:
    """(type, bits) of a SubjectPublicKeyInfo."""
    _, acs, ace = _read(data, start, end)                     # AlgorithmIdentifier
    _, ocs, oce = _read(data, acs, ace)
    algorithm = _oid(data, ocs, oce)
    btag, bcs, bce = _read(data, ace, end)                    # BIT STRING
    if btag != 0x03 or bce <= bcs:
        raise X509Error("bad public key")
    if algorithm == "1.2.840.113549.1.1.1":                   # RSA: SEQUENCE { modulus, exponent }
        _, scs, sce = _read(data, bcs + 1, bce)
        _, ics, ice = _read(data, scs, sce)
        modulus = data[ics:ice].lstrip(b"\x00")
        bits = len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else 0
        return "RSA", bits
    if algorithm == "1.2.840.10045.2.1":                      # EC: the curve is the parameter
        ctag, ccs, cce = _read(data, oce, ace)
        curve = _CURVES.get(_oid(data, ccs, cce), ("EC", 0)) if ctag == 0x06 else ("EC", 0)
        return f"EC {curve[0]}" if curve[0] != "EC" else "EC", curve[1]
    if algorithm == "1.3.101.112":
        return "Ed25519", 256
    if algorithm == "1.3.101.113":
        return "Ed448", 448
    if algorithm == "1.2.840.10040.4.1":
        return "DSA", 0
    return algorithm, 0


def _san(data: bytes, start: int, end: int) -> list:
    names: list = []
    _, scs, sce = _read(data, start, end)                     # GeneralNames
    for tag, cs, ce in _children(data, scs, sce):
        if len(names) >= MAX_SAN:
            break
        if tag == 0x82:                                       # dNSName
            names.append(data[cs:ce].decode("ascii", "replace"))
        elif tag == 0x87 and ce - cs in (4, 16):              # iPAddress
            raw = data[cs:ce]
            names.append(".".join(map(str, raw)) if len(raw) == 4
                         else ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2)))
    return names


def parse_certificate(der: bytes) -> dict:
    """Facts about a DER certificate. Raises X509Error if it cannot be read.

    Keys: subject, issuer (dicts of commonName/organizationName/...), self_signed,
    not_before, not_after (epoch seconds), serial, sig_alg, weak_sig, key_type,
    key_bits, san (list).
    """
    if not isinstance(der, (bytes, bytearray)) or not der or len(der) > MAX_DER:
        raise X509Error("no certificate data")
    data = bytes(der)
    cert_cs, cert_ce = _expect(data, 0, len(data), 0x30)
    tbs_cs, tbs_ce = _expect(data, cert_cs, cert_ce, 0x30)
    _, alg_cs, alg_ce = _read(data, tbs_ce, cert_ce)          # outer signatureAlgorithm
    otag, ocs, oce = _read(data, alg_cs, alg_ce)
    sig_oid = _oid(data, ocs, oce) if otag == 0x06 else ""
    sig_alg = _SIG_ALGS.get(sig_oid, sig_oid or "unknown")

    fields = list(_children(data, tbs_cs, tbs_ce))
    i = 0
    if fields and fields[0][0] == 0xA0:                       # [0] version
        i = 1
    try:
        serial = data[fields[i][1]:fields[i][2]].hex()
        issuer_tag, issuer_cs, issuer_ce = fields[i + 2]
        validity = fields[i + 3]
        subject_tag, subject_cs, subject_ce = fields[i + 4]
        spki = fields[i + 5]
    except IndexError:
        raise X509Error("incomplete certificate") from None
    if issuer_tag != 0x30 or subject_tag != 0x30 or validity[0] != 0x30 or spki[0] != 0x30:
        raise X509Error("unexpected structure")

    t1, c1, e1 = _read(data, validity[1], validity[2])
    t2, c2, e2 = _read(data, e1, validity[2])
    not_before, not_after = _time(t1, data[c1:e1]), _time(t2, data[c2:e2])
    key_type, key_bits = _key_info(data, spki[1], spki[2])

    san = []
    for tag, cs, ce in fields[i + 6:]:
        if tag != 0xA3:                                       # [3] extensions
            continue
        _, ecs, ece = _read(data, cs, ce)
        for _xtag, xcs, xce in _children(data, ecs, ece):
            oid_tag, o_cs, o_ce = _read(data, xcs, xce)
            if oid_tag == 0x06 and _oid(data, o_cs, o_ce) == "2.5.29.17":
                pos = o_ce
                tag2, c2_, e2_ = _read(data, pos, xce)
                if tag2 == 0x01:                              # skip the optional 'critical' flag
                    pos = e2_
                    tag2, c2_, e2_ = _read(data, pos, xce)
                if tag2 == 0x04:
                    san = _san(data, c2_, e2_)

    return {
        "subject": _name(data, subject_cs, subject_ce), "issuer": _name(data, issuer_cs, issuer_ce),
        "self_signed": data[subject_cs:subject_ce] == data[issuer_cs:issuer_ce],
        "not_before": not_before, "not_after": not_after, "serial": serial,
        "sig_alg": sig_alg, "weak_sig": "md5" in sig_alg.lower() or "sha1" in sig_alg.lower(),
        "key_type": key_type, "key_bits": key_bits, "san": san,
    }
