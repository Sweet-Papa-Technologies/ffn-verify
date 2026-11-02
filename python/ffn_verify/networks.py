"""The FFN Verified Business registries, as door-core's networks.ts pins them.

Pass ``FFN_BUSINESS_REGISTRY`` as ``registry`` to verify against the production
registry with its key pins: a record, attestation or status list signed by any key not
listed in ``keyThumbprints`` fails, even if the registry's did.json lists that key.

The production and devnet registry DIDs are pinned wherever they appear, whichever
function is called (``KNOWN_REGISTRY_KEYS``): a DidResolver keeps only these keys for
them. Keep both lists identical to ``PRODUCTION_REGISTRY_KEYS`` and
``DEVNET_REGISTRY_KEYS`` in packages/door-core/src/networks.ts (a test compares them).
"""

from __future__ import annotations

from types import MappingProxyType

PRODUCTION_REGISTRY_KEYS = (
    # KMS fofo-network-mainet ffn-pass-mainet/registry-signer (HSM), version 1: #records-1, signing.
    "ha2yRH_LpeVyIJR5KvD_3m10ZQCbe1ppRqo5Swo7B6k",
    # KMS fofo-network-mainet ffn-pass-mainet/registry-signer-2 (HSM), version 1: #records-2, standby.
    "tWuq-FfqJwjb_oqiMHELPG18U1bfCCOvNRs1s5zjroU",
)
DEVNET_REGISTRY_KEYS = (
    # KMS fofo-network-devnet ffn-pass-devnet/registry-signer, version 1: #records-1, signing.
    "Updj4FcLyO2SpdZw57NjEKEKG2SFnnoq8UBm5Pk-lZI",
    # KMS fofo-network-devnet ffn-pass-devnet/registry-signer-2, version 1: #records-2, standby.
    "X3go29ByGoAuStS_9wK7uInL-W_tIh_L4-djymN7iks",
)

FFN_BUSINESS_REGISTRY = {
    "origin": "https://registry.fofo.network",
    "did": "did:web:registry.fofo.network",
    "name": "Sweet Papa Technologies LLC",
    "keyThumbprints": list(PRODUCTION_REGISTRY_KEYS),
}

FFN_DEVNET_BUSINESS_REGISTRY = {
    "origin": "https://fofo-registry-devnet.web.app",
    "did": "did:web:fofo-registry-devnet.web.app",
    "name": "Sweet Papa Technologies LLC",
    "keyThumbprints": list(DEVNET_REGISTRY_KEYS),
}

# Registry DID -> the only key thumbprints it may sign with, in every API.
KNOWN_REGISTRY_KEYS = MappingProxyType({
    "did:web:registry.fofo.network": PRODUCTION_REGISTRY_KEYS,
    "did:web:fofo-registry-devnet.web.app": DEVNET_REGISTRY_KEYS,
})
