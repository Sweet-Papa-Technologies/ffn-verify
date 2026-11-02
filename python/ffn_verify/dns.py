"""TXT lookups for the domain binding, as verify-business's dns.ts.

DNS-over-HTTPS JSON needs nothing beyond HTTPS, so agents need no resolver library.
A resolver is any object with ``txt(name) -> list[str]``: the TXT strings at name
(each record's strings joined), ``[]`` when there are none, raising when the lookup
itself fails.
"""

from __future__ import annotations

import urllib.parse
from typing import Protocol

from ._js import array, is_num, prop
from .binding import unquote_txt
from .fetch import DEFAULT_TIMEOUT, DNS_ANSWER_MAX, Fetch, bounded_fetch, ok, text_of, urllib_fetch
from .jose import json_parse

RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}


# What encodeURIComponent leaves alone (letters, digits and _.-~ are always safe in quote).
_URI_COMPONENT_SAFE = "!*'()"


class TxtResolver(Protocol):
    def txt(self, name: str) -> list[str]: ...


class DohResolver:
    """DNS-over-HTTPS JSON. Each answer is held to 64 KiB and ``timeout`` seconds."""

    def __init__(self, provider: str = "cloudflare", fetch: Fetch | None = None, *,
                 timeout: float = DEFAULT_TIMEOUT):
        self._url = RESOLVERS[provider]
        self._fetch = fetch or urllib_fetch
        self._timeout = timeout

    def txt(self, name: str) -> list[str]:
        url = f"{self._url}?name={urllib.parse.quote(name, safe=_URI_COMPONENT_SAFE)}&type=TXT"
        status, _, body = bounded_fetch(self._fetch, url, {"accept": "application/dns-json"},
                                        max_bytes=DNS_ANSWER_MAX, timeout=self._timeout)
        if not ok(status):
            raise OSError(f"DNS lookup failed (HTTP {status})")
        data = json_parse(text_of(body))
        code = prop(data, "Status")
        # NXDOMAIN (3) is an answer: there is no record.
        if not (is_num(code) and code in (0, 3)):
            raise OSError(f"DNS lookup failed (status {code})")
        answers = [] if prop(data, "Answer") is None else array(data["Answer"], "Answer")
        return [unquote_txt(prop(a, "data")) for a in answers if is_num(prop(a, "type")) and prop(a, "type") == 16]


def doh_resolver(provider: str = "cloudflare", fetch: Fetch | None = None, *,
                 timeout: float = DEFAULT_TIMEOUT) -> DohResolver:
    return DohResolver(provider, fetch, timeout=timeout)


class StaticTxt:
    """A fixed table, for tests and test vectors."""

    def __init__(self, records: dict[str, list[str]]):
        self._records = records

    def txt(self, name: str) -> list[str]:
        return self._records.get(name.lower(), [])


def static_txt(records: dict[str, list[str]]) -> StaticTxt:
    return StaticTxt(records)
