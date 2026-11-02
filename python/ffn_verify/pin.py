"""Registry key pinning, as verify-business's pin.ts.

A verifier that pins the registry's keys accepts only those keys for the registry's
DID, whatever its did.json lists: a key added to the document by someone who got write
access to the registry's host signs nothing a pinned verifier accepts. Records,
attestations, status lists and the delegation's key binding all resolve through here,
so one filter covers every registry signature.

The known FFN registries (networks.KNOWN_REGISTRY_KEYS) are pinned in every API: a
DidResolver applies their pins itself, and ``pin_known_registries`` wraps any other
resolver a caller brings.
"""

from __future__ import annotations

from typing import Any, Iterable

from .did import DidResolver, did_web_for_origin, keep_pinned
from .jose import jwk_thumbprint
from .networks import KNOWN_REGISTRY_KEYS


def key_thumbprint(jwk: Any) -> str:
    """RFC 7638 SHA-256 thumbprint (base64url), the pin format."""
    return jwk_thumbprint(jwk)


class PinnedRegistryResolver(DidResolver):
    """``inner``, except that the registry's DID document keeps only the pinned keys."""

    def __init__(self, inner: DidResolver, registry_did: str, thumbprints: Iterable[str]):
        super().__init__()
        self._inner = inner
        self._registry_did = registry_did
        self._thumbprints = list(thumbprints)

    def resolve(self, did: str) -> dict:
        doc = self._inner.resolve(did)
        if did != self._registry_did or not isinstance(doc, dict):
            return doc
        return keep_pinned(doc, self._thumbprints)

    def key_for(self, did: str, kid: str | None, relationship: str) -> dict:
        try:
            return super().key_for(did, kid, relationship)
        except Exception:
            # Say so when the registry lists the key but this verifier doesn't pin it.
            if did == self._registry_did and kid is not None and self._lists_unpinned(did, kid, relationship):
                raise ValueError(f"{kid} is not one of the registry keys this verifier pins") from None
            raise

    def _lists_unpinned(self, did: str, kid: str, relationship: str) -> bool:
        if isinstance(self._inner, DidResolver):
            return self._inner._lists_unpinned(did, kid, relationship)
        try:
            self._inner.key_for(did, kid, relationship)
            return True
        except Exception:
            return False


def pin_registry_keys(resolver: DidResolver, registry_did: str, thumbprints: Iterable[str] | None) -> DidResolver:
    """``resolver``, limited to the pinned keys for the registry's DID; unchanged when nothing is pinned."""
    return resolver if thumbprints is None else PinnedRegistryResolver(resolver, registry_did, thumbprints)


def pin_known_registries(resolver: Any) -> DidResolver:
    """``resolver`` with the known FFN registries pinned. A DidResolver pins them itself;
    anything else is wrapped."""
    if isinstance(resolver, DidResolver):
        return resolver
    for did, thumbprints in KNOWN_REGISTRY_KEYS.items():
        resolver = PinnedRegistryResolver(resolver, did, thumbprints)
    return resolver


def registry_did_of(registry: dict) -> str:
    """The registry anchor's DID: its ``did``, else the did:web of its origin's host."""
    did = registry.get("did")
    return did if did is not None else did_web_for_origin(registry["origin"])


def registry_pins_of(registry: dict) -> list[str] | None:
    """The anchor's ``keyThumbprints``; a known FFN registry without them gets its own."""
    pins = registry.get("keyThumbprints")
    if pins is None:
        known = KNOWN_REGISTRY_KEYS.get(registry_did_of(registry))
        return list(known) if known is not None else None
    return pins


def anchored_resolver(resolver: Any, registry: dict) -> DidResolver:
    """``resolver`` with the known registries and this anchor's pins applied."""
    return pin_registry_keys(pin_known_registries(resolver), registry_did_of(registry), registry_pins_of(registry))
