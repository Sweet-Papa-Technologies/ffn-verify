"""FFN Verified Business credential kinds, levels and labels, as door-core's business.ts.

A business holds several narrow credentials rather than one big one, so each
expires and is revoked on its own schedule. The business signs its own profile and
its delegations; SPT signs only the attestations.
"""

from __future__ import annotations

VCT_BASE = "https://pass.fofo.network/vct"

BUSINESS_KINDS = {
    "businessProfile": f"{VCT_BASE}/business-profile/v1",
    "delegation": f"{VCT_BASE}/delegation/v1",
    "businessIdentity": f"{VCT_BASE}/business-identity/v1",
    "officialChannels": f"{VCT_BASE}/official-channels/v1",
    "license": f"{VCT_BASE}/license/v1",
    "insurance": f"{VCT_BASE}/insurance/v1",
    "representative": f"{VCT_BASE}/representative/v1",
}

ATTESTATION_KINDS = ("businessIdentity", "officialChannels", "license", "insurance", "representative")

KIND_LABELS = {
    "businessProfile": "Business profile",
    "delegation": "Delegation",
    "businessIdentity": "Business identity",
    "officialChannels": "Official channels",
    "license": "License",
    "insurance": "Insurance",
    "representative": "Verified representative",
}

LEVEL_NAMES = {0: "Not verified", 1: "Registered", 2: "Licensed and insured", 3: "Owner verified"}

# What each level needs, cumulatively.
LEVEL_REQUIREMENTS = {
    1: ("businessIdentity", "officialChannels"),
    2: ("businessIdentity", "officialChannels", "license", "insurance"),
    3: ("businessIdentity", "officialChannels", "license", "insurance", "representative"),
}

# The delegation every listing carries: the business lets the registry publish and serve its record.
REGISTRY_SCOPES = ("registry:publish", "registry:serve")

BUSINESS_RECORD_TYP = "ffn-business-record+jwt"


def kind_for_vct(vct: str) -> str | None:
    for kind, value in BUSINESS_KINDS.items():
        if value == vct:
            return kind
    return None


def level_for(valid: set[str]) -> int:
    for level in (3, 2, 1):
        if all(k in valid for k in LEVEL_REQUIREMENTS[level]):
            return level
    return 0
