"""IETF Token Status List checks, as door-core's status.ts.

Principle 1 (FFN v1): never block on FFN or an issuer being down. A list that can't
be fetched falls back to the last verified copy; with none, the status is "unknown"
and the caller decides what that means for it.

A status list token is a JWT (typ statuslist+jwt) whose payload carries
``status_list: {bits, lst}``: ``lst`` is base64url of zlib-deflated bytes, entries
packed LSB-first. 0 = valid, 1 = invalid, 2 = suspended. A list that inflates past
16 MiB fails like a list that can't be fetched.
"""

from __future__ import annotations

import time
import zlib
from typing import Any, Callable, MutableMapping

from ._egress import check_public_https
from ._js import is_num, iso, opt, prop, trim, truthy
from .did import DidResolver, did_web_for_origin
from .fetch import DEFAULT_TIMEOUT, STATUS_LIST_MAX, Fetch, bounded_fetch, ok, text_of, urllib_fetch
from .jose import b64u_decode, decode_jwt, header_kid, verify_jwt

WEEK = 7 * 86_400


# A list's bits once inflated: a 2 MiB list could otherwise expand a thousandfold.
STATUS_LIST_INFLATED_MAX = 16 * 1024 * 1024
_CHUNK = 64 * 1024


def inflate_status_list(lst: Any, cap: int = STATUS_LIST_INFLATED_MAX) -> bytes:
    """A list's ``lst`` inflated (zlib, or gzip as the token status list library also
    accepts), refusing one that inflates past ``cap`` bytes before inflating any further."""
    if not isinstance(lst, str):
        raise ValueError("status list has no lst")
    compressed = b64u_decode(lst)
    gzip = compressed[:2] == b"\x1f\x8b"
    inflater = zlib.decompressobj(31 if gzip else 15)
    out = bytearray()
    data = compressed
    try:
        while not inflater.eof:
            # Never more than one byte past the cap, so a bomb stops right there.
            chunk = inflater.decompress(data, min(_CHUNK, cap + 1 - len(out)))
            out += chunk
            if len(out) > cap:
                raise ValueError("status list inflates past the size cap")
            data = inflater.unconsumed_tail
            if not chunk and not data:
                break
    except zlib.error as err:
        raise ValueError(f"status list does not inflate: {err}") from None
    if not inflater.eof:
        raise ValueError("status list does not inflate: incomplete")
    if inflater.unused_data:
        raise ValueError("status list does not inflate: data after its end")
    return bytes(out)


def status_at(bits: int, raw: bytes, idx: float) -> int | None:
    """The status at ``idx``, read straight from the bytes (least significant bits
    first, as the Token Status List draft packs them). A non-integer index reads as
    no value, which the caller counts as invalid."""
    total = len(raw) * 8 // bits
    if idx < 0 or idx >= total:
        raise IndexError("Index out of bounds")
    if idx != int(idx):
        return None
    bit = int(idx) * bits
    return (raw[bit >> 3] >> (bit & 7)) & ((1 << bits) - 1)


def verify_status_list_claims(payload: Any, *, uri: str, now: float, skew: float = 30) -> None:
    """The library's verifyStatusListJwtClaims with checkFreshness off, at ``now``."""
    sub, iat, nbf, exp = prop(payload, "sub"), prop(payload, "iat"), prop(payload, "nbf"), prop(payload, "exp")
    if not isinstance(sub, str):
        raise ValueError("The status list token has no subject claim, which is required")
    if sub != uri:
        raise ValueError(f"The subject claim '{sub}' must be equal to the uri '{uri}'")
    if is_num(exp) and exp + skew < now:
        raise ValueError(f"The expiration claim '{iso(exp)}' is in the past (compared to '{iso(now)}'), "
                         "and therefore not valid")
    if not is_num(iat):
        raise ValueError("The status list token has no issued at claim, which is required")
    if is_num(nbf) and nbf - skew > now:
        raise ValueError(f"The not before claim '{iso(nbf)}' is in the future (compared to '{iso(now)}'), "
                         "and therefore not valid")


class StatusChecker:
    """Status of the entry a credential's ``status.status_list`` points at.

    ``store`` is the last-good cache (any dict-like, in-memory by default), keyed by
    list URI. ``now`` returns seconds since epoch (default: the clock). Each list fetch
    is held to 2 MiB and ``timeout`` seconds, to an https URI on a public host.
    """

    def __init__(self, *, resolver: DidResolver, fetch: Fetch | None = None,
                 store: MutableMapping[str, dict] | None = None, max_age_seconds: float = 3600,
                 now: Callable[[], float] | None = None, timeout: float = DEFAULT_TIMEOUT):
        self._resolver = resolver
        self._fetch = fetch or urllib_fetch
        self._store = {} if store is None else store
        self._max_age_ms = max_age_seconds * 1000
        self._now = now or (lambda: int(time.time()))
        self._timeout = timeout

    def _cached(self, uri: str) -> dict | None:
        entry = self._store.get(uri)
        # Kept a week, as the TS store's TTL.
        if entry and self._now() * 1000 <= entry["fetchedAt"] + WEEK * 1000:
            return entry
        return None

    def check(self, ref: Any, issuer: str) -> dict:
        """The list must be signed by the root DID of the host serving it
        (``https://<host>/...`` -> ``did:web:<host>``, no path), resolved through this
        checker's resolver, so a known registry's list counts only under its pinned keys.
        ``issuer`` (the credential's issuer) is kept for compatibility; it no longer
        widens who may sign. Raises when the reference is missing or its URI is not an
        https URI on a public host (no request is made). Returns {status, checkedAt?}."""
        entry = opt(ref, "status_list")
        if not truthy(entry) or not is_num(prop(entry, "idx")) or not isinstance(prop(entry, "uri"), str):
            raise ValueError("credential has no status reference")
        uri = entry["uri"]
        check_public_https(uri, "status list URI")
        cached = self._cached(uri)
        token = cached if cached and self._now() * 1000 - cached["fetchedAt"] < self._max_age_ms else None
        bits_raw = None
        if not token:
            try:
                status, _, body = bounded_fetch(self._fetch, uri, {"accept": "application/statuslist+jwt"},
                                                max_bytes=STATUS_LIST_MAX, timeout=self._timeout)
                if not ok(status):
                    raise ValueError(f"HTTP {status}")
                fresh = {"jwt": trim(text_of(body)), "fetchedAt": self._now() * 1000}
                bits_raw = self._verify_token(fresh["jwt"], uri, issuer)
                token = fresh
                self._store[uri] = token
            except Exception:
                token = cached
        if not token:
            return {"status": "unknown"}
        if bits_raw is None:
            bits_raw = self._verify_token(token["jwt"], uri, issuer)
        value = status_at(*bits_raw, entry["idx"])
        status = "valid" if value == 0 else "suspended" if value == 2 else "invalid"
        return {"status": status, "checkedAt": iso(token["fetchedAt"] / 1000)}

    def _verify_token(self, jwt: str, uri: str, issuer: str) -> tuple[int, bytes]:
        """Verify the list's signer, signature and claims; return (bits, inflated bytes)."""
        header, payload, _, _ = decode_jwt(jwt)
        list_issuer = prop(payload, "iss")
        if not isinstance(list_issuer, str):
            raise ValueError("status list has no issuer")
        # Only the host's root DID: a path DID on the same host (did:web:<host>:anything)
        # is whoever can write a file there, not the host.
        if list_issuer != did_web_for_origin(uri):
            raise ValueError("status list is not signed by its host's DID")
        key = self._resolver.assertion_key(list_issuer, header_kid(header))
        # Lists are re-signed daily; an old signature is still a signature, so a
        # week of skew keeps last-good copies usable through an outage.
        _, verified = verify_jwt(jwt, key, typ="statuslist+jwt", skew=WEEK, now=self._now())
        # The same clock and week of skew as the signature check, so a last-good copy
        # outlives a day-long outage and test vectors replay at their own now.
        verify_status_list_claims(verified, uri=uri, now=self._now(), skew=WEEK)
        status_list = prop(verified, "status_list")
        bits = opt(status_list, "bits")
        if not is_num(bits) or bits not in (1, 2, 4, 8):
            raise ValueError("status list bits must be 1, 2, 4 or 8")
        return int(bits), inflate_status_list(opt(status_list, "lst"))
