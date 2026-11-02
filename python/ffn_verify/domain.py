"""Normalizing the identifiers a business is looked up by, as door-core's domain.ts.

Lookups compare normalized forms only, so ``ACME-HVAC.example.`` and ``acme-hvac.example``
are the same entry and a homoglyph (``аcme-hvac.com``, Cyrillic а) becomes its own
punycode name that no verified business lists.
"""

from __future__ import annotations

import re
import unicodedata

from ._js import JS_WS_CLASS, trim
from .url import URL


class IdentifierError(ValueError):
    pass


PRIVATE_SUFFIXES = ("internal", "local", "localhost", "localdomain", "home.arpa", "lan", "intranet")
_NOT_A_HOST = re.compile(JS_WS_CLASS[:-1] + "/?#@:]")
_IPV4 = re.compile(r"[0-9]+(\.[0-9]+){3}")


def normalize_domain(value: str) -> str:
    """Lowercase ASCII (punycode) host name, no trailing dot, port, path or IP address."""
    raw = re.sub(r"\.\Z", "", trim(value))
    if not raw or _NOT_A_HOST.search(raw):
        raise IdentifierError(f"not a domain: {value}")
    try:
        host = URL(f"https://{raw}/").hostname
    except ValueError:
        raise IdentifierError(f"not a domain: {value}") from None
    if _IPV4.fullmatch(host) or host.startswith("["):
        raise IdentifierError("IP addresses are not business domains")
    labels = host.split(".")
    if len(labels) < 2 or any(len(label) == 0 or len(label) > 63 for label in labels):
        raise IdentifierError(f"not a domain: {value}")
    # Names that only resolve inside a network (e.g. metadata.google.internal) are never a business.
    if any(host == s or host.endswith(f".{s}") for s in PRIVATE_SUFFIXES):
        raise IdentifierError(f"not a public domain: {value}")
    return host


def normalize_phone(value: str) -> str:
    """E.164 form of a phone number. Ten-digit numbers are taken as US/Canada (NANP),
    the only region v1 verifies; anything else must already carry its country code."""
    trimmed = trim(value)
    digits = re.sub(r"[^0-9]", "", trimmed)  # JS \d is ASCII only
    if trimmed.startswith("+"):
        if len(digits) < 8 or len(digits) > 15:
            raise IdentifierError(f"not a phone: {value}")
        return f"+{digits}"
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    raise IdentifierError(f"not a phone number with a country code: {value}")


_LEGAL_SUFFIX = re.compile(r"\b(inc|incorporated|llc|l l c|ltd|co|corp|corporation|company|the)\b")


def name_key(name: str) -> str:
    """Loose comparison form of a business name: case, punctuation and legal suffixes ignored."""
    s = re.sub("[̀-ͯ]", "", unicodedata.normalize("NFKD", name)).lower()
    s = re.sub(r"[^a-z0-9 ]+", " ", s.replace("&", " and "))
    s = _LEGAL_SUFFIX.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()
