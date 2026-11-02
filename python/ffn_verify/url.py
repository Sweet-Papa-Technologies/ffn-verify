"""The slice of the WHATWG URL parser the verifier depends on.

The TS verifier reads ``new URL(x).host``, ``.hostname`` and ``.pathname`` in three
places: normalizing a domain, checking that a DID document's registry entry points
at the pinned registry, and the rule for which host may sign a status list. Python's
urllib parses differently (``https://evil.com\\@registry.test/`` is ``evil.com`` to a
browser, ``registry.test`` to urlsplit), so this follows the WHATWG algorithm for
absolute URLs instead.

Domain to ASCII approximates UTS #46 as WHATWG runs it (non-transitional, no STD3
rules, no DNS length check) with the standard library: NFKC plus per-character
lowercasing stands in for the IDNA mapping table, then Punycode, with label validity
(leading combining marks, joiners, the bidi rule) checked the way Node 22's parser
(ada) checks it, including where ada departs from RFC 5893. It matched Node on 18,000
randomized hostnames; the joining-type table for ZWNJ covers Arabic, Syriac and
Mongolian only.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

SPECIAL_PORTS = {"ftp": 21, "file": None, "http": 80, "https": 443, "ws": 80, "wss": 443}

_FORBIDDEN_HOST = set("\x00\t\n\r #/:<>?@[\\]^|")
_FORBIDDEN_DOMAIN = _FORBIDDEN_HOST | {chr(c) for c in range(0x20)} | {"%", "\x7f"}
# Default-ignorable characters UTS #46 maps to nothing.
_IGNORED = set("­͏᠋᠌᠍᠏​⁠⁤﻿") | {
    chr(c) for c in [*range(0xFE00, 0xFE10), *range(0x1BCA0, 0x1BCA4), *range(0xE0100, 0xE01F0)]
}
_DISALLOWED_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"}


class URLError(ValueError):
    pass


def _percent_decode(s: str) -> bytes:
    raw = s.encode("utf-8", "surrogatepass")
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == 0x25 and re.fullmatch(rb"[0-9A-Fa-f]{2}", raw[i + 1:i + 3]):
            out.append(int(raw[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return bytes(out)


_FULL_STOPS = {".", "\uff0e", "\u3002", "\uff61"}


def _uts46_map(s: str) -> str:
    out = []
    for c in s:
        if c in _IGNORED:
            continue
        mapped = unicodedata.normalize("NFKC", c)
        if "." in mapped and c not in _FULL_STOPS:
            raise URLError("disallowed character")  # e.g. \u2488 (digit full stop)
        # Per character, so a final sigma maps to σ as UTS #46 does, not ς as str.lower() would.
        out.append("".join(ch.lower() for ch in mapped))
    return unicodedata.normalize("NFC", "".join(out)).replace("\u3002", ".")


# Joining types for the ZWNJ context rule. Python has no ArabicShaping data, so this
# covers Arabic, Syriac and Mongolian letters; other joining scripts read as non-joining.
_ARABIC_R = {0x0622, 0x0623, 0x0624, 0x0625, 0x0627, 0x0629, 0x062F, 0x0630, 0x0631, 0x0632, 0x0648, 0x0671,
             0x0672, 0x0673, 0x0675, 0x0676, 0x0677, *range(0x0688, 0x069A), 0x06C0, *range(0x06C3, 0x06CC), 0x06CD,
             0x06CF, 0x06D2, 0x06D3, 0x06D5, 0x06EE, 0x06EF, 0x0759, 0x075A, 0x075B, 0x076B, 0x076C, 0x0771, 0x0773,
             0x0774, 0x0778, 0x0779, *range(0x0870, 0x0883), 0x088E, 0x08AA, 0x08AB, 0x08AC, 0x08AE, 0x08B1, 0x08B2,
             0x08B9, 0x0710, *range(0x0715, 0x071A), 0x071E, 0x0728, 0x072A, 0x072C, 0x072F, 0x074D}
_ARABIC_U = {0x0621, 0x0640, 0x0674}


def _joining_type(c: str) -> str:
    cp, cat = ord(c), unicodedata.category(c)
    if cat in ("Mn", "Me", "Cf"):
        return "T"
    if cat != "Lo":
        return "U"
    if cp in _ARABIC_R:
        return "R"
    if cp in _ARABIC_U:
        return "U"
    if any(lo <= cp <= hi for lo, hi in ((0x0620, 0x06FF), (0x0710, 0x074F), (0x0750, 0x077F), (0x0860, 0x08FF),
                                          (0x1820, 0x1878), (0x1887, 0x18A8))):
        return "D"
    return "U"


def _zwnj_ok(label: str, i: int) -> bool:
    # Node 22's ada looks for a left- or dual-joining letter anywhere before the ZWNJ and a
    # right- or dual-joining one anywhere after it (RFC 5892 only skips transparent marks).
    return (any(_joining_type(c) in ("L", "D") for c in label[:i])
            and any(_joining_type(c) in ("R", "D") for c in label[i + 1:]))


_LTR_ALLOWED = {"L", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"}
_RTL_ALLOWED = {"R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"}


def _valid_label(label: str) -> bool:
    """UTS #46 label validity as Node 22's URL parser (ada) applies it."""
    if not label:
        return True
    for c in label:
        if c != "\u200c" and c != "\u200d" and ord(c) > 0x7F and (
                c == "\ufffd" or unicodedata.category(c) in _DISALLOWED_CATEGORIES):
            return False
    if unicodedata.category(label[0]).startswith("M"):
        return False  # must not begin with a combining mark
    for i, c in enumerate(label):
        # ada settles the label at its first joiner: no bidi checks follow.
        if c in "\u200c\u200d":
            if i > 0 and unicodedata.combining(label[i - 1]) == 9:
                return True  # after a virama
            return c == "\u200c" and _zwnj_ok(label, i)
    bidi = [unicodedata.bidirectional(c) for c in label]
    last = max((i for i, d in enumerate(bidi) if d != "NSM"), default=-1)
    if last < 0:
        return False
    if not any(d in ("R", "AL", "AN") for d in bidi):
        return True
    # Bidi rule (RFC 5893), in the shape Node applies it: an L-first label only
    # constrains what precedes its last non-NSM character.
    if bidi[0] == "L":
        return all(d in _LTR_ALLOWED for d in bidi[:last])
    return (all(d in _RTL_ALLOWED for d in bidi) and bidi[last] in ("R", "AL", "EN", "AN")
            and not ("EN" in bidi and "AN" in bidi))


def domain_to_ascii(domain: str) -> str:
    mapped = _uts46_map(domain)
    labels = []
    for label in mapped.split("."):
        if label.startswith("xn--"):
            try:
                decoded = label[4:].encode("ascii").decode("punycode")
            except Exception:
                raise URLError("invalid punycode") from None
            if not decoded or not _valid_label(decoded) or _uts46_map(decoded) != decoded:
                raise URLError("invalid punycode")
            labels.append(label)
        elif label.isascii():
            labels.append(label)
        else:
            if not _valid_label(label):
                raise URLError("disallowed character")
            labels.append("xn--" + label.encode("punycode").decode("ascii"))
    result = ".".join(labels)
    if not result:
        raise URLError("empty host")
    return result


def _ipv4_number(part: str) -> int | None:
    if part == "":
        return None
    radix = 10
    if part[:2] in ("0x", "0X"):
        part, radix = part[2:], 16
    elif len(part) > 1 and part[0] == "0":
        part, radix = part[1:], 8
    if part == "":
        return 0
    digits = {10: "0123456789", 16: "0123456789abcdefABCDEF", 8: "01234567"}[radix]
    if not all(c in digits for c in part):
        return None
    return int(part, radix)


def _ends_in_number(host: str) -> bool:
    parts = host.split(".")
    if parts[-1] == "":
        if len(parts) == 1:
            return False
        parts.pop()
    last = parts[-1]
    if last and all(c in "0123456789" for c in last):
        return True
    return _ipv4_number(last) is not None


def _ipv4(host: str) -> str:
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        raise URLError("invalid IPv4 address")
    numbers = [_ipv4_number(p) for p in parts]
    if any(n is None for n in numbers) or any(n > 255 for n in numbers[:-1]):
        raise URLError("invalid IPv4 address")
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        raise URLError("invalid IPv4 address")
    value = numbers[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(numbers[:-1]))
    return ".".join(str((value >> s) & 0xFF) for s in (24, 16, 8, 0))


def _ipv6(inner: str) -> str:
    try:
        packed = ipaddress.IPv6Address(inner).packed
    except ValueError:
        raise URLError("invalid IPv6 address") from None
    pieces = [int.from_bytes(packed[i:i + 2], "big") for i in range(0, 16, 2)]
    # Compress the first longest run of two or more zero pieces.
    best, best_len, i = -1, 1, 0
    while i < 8:
        if pieces[i] == 0:
            j = i
            while j < 8 and pieces[j] == 0:
                j += 1
            if j - i > best_len:
                best, best_len = i, j - i
            i = j
        else:
            i += 1
    if best < 0:
        return "[" + ":".join(f"{p:x}" for p in pieces) + "]"
    head = ":".join(f"{p:x}" for p in pieces[:best])
    tail = ":".join(f"{p:x}" for p in pieces[best + best_len:])
    return f"[{head}::{tail}]"


def parse_host(raw: str, special: bool = True) -> str:
    """The host parser: IPv6, opaque host (non-special schemes), domain or IPv4."""
    if raw.startswith("["):
        if not raw.endswith("]"):
            raise URLError("unclosed IPv6 address")
        return _ipv6(raw[1:-1])
    if not special:
        if any(c in _FORBIDDEN_HOST for c in raw if c != "%"):
            raise URLError("forbidden host code point")
        return "".join(c if 0x20 < ord(c) < 0x7F else _pct(c) for c in raw)
    domain = _percent_decode(raw).decode("utf-8", "replace")
    ascii_domain = domain_to_ascii(domain)
    if any(c in _FORBIDDEN_DOMAIN for c in ascii_domain):
        raise URLError("forbidden domain code point")
    return _ipv4(ascii_domain) if _ends_in_number(ascii_domain) else ascii_domain


def _pct(c: str) -> str:
    return "".join(f"%{b:02X}" for b in c.encode("utf-8", "surrogatepass"))


# Path percent-encode set: C0 controls, space, ", #, <, >, ?, `, {, } and anything above ~.
_PATH_ENCODE = set(' "#<>?`{}') | {chr(c) for c in range(0x20)}


def _encode_path_segment(seg: str) -> str:
    return "".join(_pct(c) if c in _PATH_ENCODE or ord(c) > 0x7E else c for c in seg)


def _path(raw: str, special: bool) -> str:
    if special:
        raw = raw.replace("\\", "/")
    if not raw.startswith("/"):
        raw = "/" + raw
    out: list[str] = []
    parts = raw[1:].split("/")
    for i, seg in enumerate(parts):
        last = i == len(parts) - 1
        low = seg.lower()
        if low in ("..", ".%2e", "%2e.", "%2e%2e"):
            if out:
                out.pop()
            if last:
                out.append("")
        elif low in (".", "%2e"):
            if last:
                out.append("")
        else:
            out.append(_encode_path_segment(seg))
    return "/" + "/".join(out)


class URL:
    """new URL(input) for an absolute URL: scheme, host (with a non-default port) and pathname."""

    def __init__(self, url: str):
        if not isinstance(url, str):
            raise URLError("not a URL")
        s = url.strip("".join(chr(c) for c in range(0x21)))
        s = re.sub(r"[\t\n\r]", "", s)
        m = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*):", s)
        if not m:
            raise URLError(f"Invalid URL: {url}")
        self.scheme = m.group(1).lower()
        rest = s[m.end():]
        special = self.scheme in SPECIAL_PORTS
        self.host = ""
        self.hostname = ""
        if self.scheme == "file" and not re.match(r"[/\\]{2}", rest):
            self.pathname = _path(re.split(r"[?#]", rest, maxsplit=1)[0], True)
        elif special or rest.startswith("//"):
            if self.scheme == "file":
                rest = rest[2:]
                stop = re.search(r"[/\\?#]", rest)
            elif special:
                rest = rest.lstrip("/\\")
                stop = re.search(r"[/\\?#]", rest)
            else:
                rest = rest[2:]
                stop = re.search(r"[/?#]", rest)
            authority, rest = (rest[:stop.start()], rest[stop.start():]) if stop else (rest, "")
            hostport = authority.rpartition("@")[2]
            if hostport.startswith("["):
                close = hostport.find("]")
                host_raw, port_raw = (hostport[:close + 1], hostport[close + 1:]) if close >= 0 else (hostport, "")
                if port_raw and not port_raw.startswith(":"):
                    raise URLError("invalid host")
                port_raw = port_raw[1:]
            else:
                host_raw, _, port_raw = hostport.partition(":")
            if port_raw and not port_raw.isdigit():
                raise URLError("invalid port")
            port = int(port_raw) if port_raw else None
            if port is not None and port > 65535:
                raise URLError("invalid port")
            if special and self.scheme != "file" and host_raw == "":
                raise URLError("missing host")
            self.hostname = parse_host(host_raw, special) if host_raw else ""
            if self.scheme == "file" and self.hostname == "localhost":
                self.hostname = ""
            if port is not None and port == SPECIAL_PORTS.get(self.scheme):
                port = None
            self.host = self.hostname + (f":{port}" if port is not None else "")
            path = re.split(r"[?#]", rest, maxsplit=1)[0]
            self.pathname = _path(path, special) if special or path else ""
        else:
            # Opaque path, e.g. did:web:example.com
            path = re.split(r"[?#]", rest, maxsplit=1)[0]
            self.pathname = "".join(c if 0x1F < ord(c) < 0x7F else _pct(c) for c in path)
