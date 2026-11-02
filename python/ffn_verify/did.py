"""did:web resolution over HTTPS and did:jwk locally, as door-core's did-web.ts and did-jwk.ts.

did:web: https://w3c-ccg.github.io/did-method-web/ (one HTTPS fetch, no redirects).
did:jwk: the DID is the public key; people and key-only businesses use one.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any

from ._egress import check_public_https
from ._js import JS_WS_CLASS, array, iterable, nullish, prop, truthy
from .fetch import (DEFAULT_TIMEOUT, DID_DOCUMENT_MAX, Fetch, FetchTimeout, ResponseTooLarge, bounded_fetch, ok,
                    text_of, urllib_fetch)
from .jose import b64u_decode_json, b64u_encode, json_parse, jwk_thumbprint, utf8
from .networks import KNOWN_REGISTRY_KEYS
from .url import URL

DID_JWK = "did:jwk:"
_URL_SHAPE = re.compile(JS_WS_CLASS[:-1] + "/?#@\\\\]")


def _decode_uri_component(s: str) -> str:
    # decodeURIComponent throws on a stray % or bytes that aren't UTF-8.
    if re.search(r"%(?![0-9A-Fa-f]{2})", s):
        raise ValueError("URI malformed")
    try:
        return urllib.parse.unquote(s, errors="strict")
    except UnicodeDecodeError:
        raise ValueError("URI malformed") from None


def is_did_jwk(did: str) -> bool:
    return did.startswith(DID_JWK)


def _canonical(jwk: Any) -> dict:
    """Members kept in the DID, in RFC 7638 order."""
    if prop(jwk, "kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
        raise ValueError("did:jwk here supports P-256 public keys only")
    return {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}


def did_jwk_for(public_jwk: Any) -> str:
    canonical = json.dumps(_canonical(public_jwk), separators=(",", ":"), ensure_ascii=False)
    return f"{DID_JWK}{b64u_encode(utf8(canonical))}"


def jwk_of_did_jwk(did: str) -> dict:
    if not is_did_jwk(did):
        raise ValueError(f"not a did:jwk: {did}")
    encoded = did[len(DID_JWK):].split("#")[0]
    jwk = b64u_decode_json(encoded)
    if not isinstance(jwk, (dict, list)):
        raise TypeError("cannot use 'in' operator on a primitive")
    if "d" in jwk:
        raise ValueError("did:jwk must not carry a private key")
    key = _canonical(jwk)
    # One key, one DID: aliases with other member orders or extra members are refused.
    if f"{DID_JWK}{encoded}" != did_jwk_for(key):
        raise ValueError("did:jwk is not in canonical form")
    return key


def resolve_did_jwk(did: str) -> dict:
    id_ = did.split("#")[0]
    vm = f"{id_}#0"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": id_,
        "verificationMethod": [
            {"id": vm, "type": "JsonWebKey2020", "controller": id_, "publicKeyJwk": jwk_of_did_jwk(id_)},
        ],
        "assertionMethod": [vm],
        "authentication": [vm],
        "capabilityDelegation": [vm],
        "capabilityInvocation": [vm],
    }


def did_web_url(did: str) -> str:
    """did:web:pass.fofo.network -> https://pass.fofo.network/.well-known/did.json"""
    if not did.startswith("did:web:"):
        raise ValueError(f"not a did:web: {did}")
    host, *path = did[len("did:web:"):].split(":")
    if not host:
        raise ValueError(f"malformed did:web: {did}")
    decoded = _decode_uri_component(host)
    # Only a port may be percent-encoded into the host; anything that changes the URL's shape is refused.
    if _URL_SHAPE.search(decoded) or any(_URL_SHAPE.search(_decode_uri_component(p)) for p in path):
        raise ValueError(f"malformed did:web: {did}")
    origin = f"https://{decoded}"
    if not path:
        return f"{origin}/.well-known/did.json"
    return f"{origin}/{'/'.join(_decode_uri_component(p) for p in path)}/did.json"


def did_web_host(did: str) -> str:
    """The host a did:web lives on (decoded): did:web:example.com:agents:booking -> example.com"""
    if not did.startswith("did:web:"):
        raise ValueError(f"not a did:web: {did}")
    return _decode_uri_component(did[len("did:web:"):].split(":")[0].split("#")[0])


def did_web_for_origin(origin: str) -> str:
    """Inverse of did_web_url for an origin with no path, as didWebForOrigin:
    https://registry.example:8443 -> did:web:registry.example%3A8443"""
    return f"did:web:{urllib.parse.quote(URL(origin).host, safe=_URI_COMPONENT_SAFE)}"


# What encodeURIComponent leaves alone (quote always keeps letters, digits and _.-~).
_URI_COMPONENT_SAFE = "!*'()"


class DidResolutionError(ValueError):
    """resolve() could not produce the document. ``missing`` is True when the host
    answered that there is none (a 4xx, or a document for another DID): an answer, not
    an outage. Messages never carry the remote status or body."""

    def __init__(self, message: str, *, missing: bool = False):
        super().__init__(message)
        self.missing = missing


def keep_pinned(doc: dict, thumbprints: Any) -> dict:
    """``doc`` with only the verification methods whose key thumbprint is pinned."""
    methods = []
    for m in array(nullish(doc.get("verificationMethod"), []), "verificationMethod"):
        try:
            pinned = jwk_thumbprint(nullish(prop(m, "publicKeyJwk"), {})) in thumbprints
        except Exception:
            pinned = False
        if pinned:
            methods.append(m)
    return {**doc, "verificationMethod": methods}


def _known_pins(did: str, doc: Any) -> Any:
    """A known FFN registry DID resolves only to its pinned keys, whoever resolved it."""
    thumbprints = KNOWN_REGISTRY_KEYS.get(did)
    return keep_pinned(doc, thumbprints) if thumbprints is not None and isinstance(doc, dict) else doc


def unique_key(doc: Any, did: str, kid: str | None, relationship: str) -> dict:
    """The key named by kid that doc lists under relationship. With no kid, the only one."""
    full_kid = None
    if kid is not None:
        full_kid = kid if kid.startswith("did:") else f"{did}#{kid[1:] if kid.startswith('#') else kid}"
    if full_kid and not full_kid.startswith(f"{did}#"):
        raise ValueError("kid does not belong to issuer")
    allowed = _ids(doc.get(relationship))
    candidates = [
        m for m in array(_nullish(doc.get("verificationMethod"), []), "verificationMethod")
        if truthy(prop(m, "publicKeyJwk")) and _listed(allowed, prop(m, "id"))
        and (full_kid is None or m.get("id") == full_kid)
    ]
    if len(candidates) != 1:
        raise ValueError(f"no unique {relationship} key {kid or ''} in {did}")
    return candidates[0]["publicKeyJwk"]


def _nullish(v: Any, default: Any) -> Any:
    return default if v is None else v


def _ids(methods: Any) -> set:
    """Method ids a relationship lists, as strings or embedded methods."""
    out = set()
    for m in array(_nullish(methods, []), "verification relationship"):
        i = m if isinstance(m, str) else prop(m, "id")
        if i is None or isinstance(i, str):  # other ids can never equal a parsed method's id
            out.add(i)
    return out


def _listed(allowed: set, method_id: Any) -> bool:
    return (method_id is None or isinstance(method_id, str)) and method_id in allowed


class DidResolver:
    """Every DID method the verifier needs: did:web over HTTPS, did:jwk locally.

    Resolved did:web documents are cached for ``ttl_seconds``; when a host is briefly
    down, a cached copy up to ``max_stale_seconds`` past its ttl is used rather than
    failing (design principle 1), so a key rotated out doesn't live on for long while
    the site is down. Each fetch is held to ``max_bytes`` and ``timeout`` seconds, to an
    https URL on a public host, with no redirects. The known FFN registry DIDs resolve
    only to their pinned keys (networks.KNOWN_REGISTRY_KEYS), including ``documents``.
    """

    def __init__(self, *, fetch: Fetch | None = None, ttl_seconds: float = 3600,
                 documents: dict[str, dict] | None = None, max_bytes: int = DID_DOCUMENT_MAX,
                 max_stale_seconds: float = 86_400, timeout: float = DEFAULT_TIMEOUT):
        self._fetch = fetch or urllib_fetch
        self._ttl = ttl_seconds
        self._pinned = documents or {}
        self._max_bytes = max_bytes  # business hosts are untrusted
        self._max_stale = max_stale_seconds
        self._timeout = timeout
        self._cache: dict[str, tuple[dict, float]] = {}
        self._raw: dict[str, dict] = {}  # known registry documents as served, to explain a pin miss

    def resolve(self, did: str) -> dict:
        doc = self._document(did)
        if did in KNOWN_REGISTRY_KEYS and isinstance(doc, dict):
            self._raw[did] = doc
        return _known_pins(did, doc)

    def _document(self, did: str) -> dict:
        if is_did_jwk(did):
            return resolve_did_jwk(did)
        if did in self._pinned:
            return self._pinned[did]
        hit = self._cache.get(did)
        if hit and hit[1] > time.time():
            return hit[0]
        missing = False
        try:
            url = did_web_url(did)
            check_public_https(url, "the DID document URL")
            try:
                # No redirects: a did:web is the document at exactly this URL.
                status, _, body = bounded_fetch(self._fetch, url, {"accept": "application/did+json, application/json"},
                                                max_bytes=self._max_bytes, timeout=self._timeout)
            except FetchTimeout:
                raise ValueError("timed out") from None
            except ResponseTooLarge:
                raise ValueError("DID document too large") from None
            except Exception:
                raise ValueError("unreachable") from None
            if not ok(status):
                missing = 400 <= status <= 499
                raise ValueError("not found" if missing else "the host did not serve it")
            try:
                doc = json_parse(text_of(body))
            except Exception:
                raise ValueError("not a JSON document") from None
            if prop(doc, "id") != did:
                missing = True
                raise ValueError("document id does not match")
            self._cache[did] = (doc, time.time() + self._ttl)
            return doc
        except Exception as err:
            if hit and time.time() - hit[1] < self._max_stale:
                return hit[0]
            raise DidResolutionError(f"could not resolve {did}: {err}", missing=missing) from None

    def assertion_key(self, did: str, kid: str | None) -> dict:
        """The assertion key named by a JWS kid (full DID URL or bare fragment)."""
        return self.key_for(did, kid, "assertionMethod")

    def key_for(self, did: str, kid: str | None, relationship: str) -> dict:
        """The key named by kid that did lists under relationship. With no kid, the only one."""
        if is_did_jwk(did) and kid is not None and not kid.startswith("did:"):
            kid = f"{did}#0"
        doc = _known_pins(did, self.resolve(did))  # again, for subclasses that resolve on their own
        try:
            return unique_key(doc, did, kid, relationship)
        except ValueError:
            if kid is not None and did in KNOWN_REGISTRY_KEYS and self._lists_unpinned(did, kid, relationship):
                raise ValueError(f"{kid} is not one of the registry keys this verifier pins") from None
            raise

    def _lists_unpinned(self, did: str, kid: str, relationship: str) -> bool:
        """Does the document as served list this key, before pins? (Only to say why a key failed.)"""
        raw = self._raw.get(did)
        if raw is None:
            if did in KNOWN_REGISTRY_KEYS:
                return False
            try:
                self.key_for(did, kid, relationship)
                return True
            except Exception:
                return False
        try:
            unique_key(raw, did, kid, relationship)
            return True
        except Exception:
            return False

    def controls_key(self, did: str, jwk: Any,
                     relationships: tuple[str, ...] = ("authentication", "assertionMethod")) -> bool:
        """Does did currently list jwk under any of relationships? This is how a credential
        bound to a key (cnf) is tied to a DID that can rotate its keys."""
        doc = _known_pins(did, self.resolve(did))
        allowed = set().union(*(_ids(doc.get(r)) for r in relationships))
        want = jwk_thumbprint(jwk)
        for m in iterable(_nullish(doc.get("verificationMethod"), []), "verificationMethod"):
            if not truthy(prop(m, "publicKeyJwk")) or not _listed(allowed, prop(m, "id")):
                continue
            if jwk_thumbprint(m["publicKeyJwk"]) == want:
                return True
        return False
