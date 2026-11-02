"""FFN Verified Business public verifier.

verify_business(domain): registry record, both signatures, status, domain binding
and delegation, no wallet needed. A port of @fofonet/verify-business; both replay
the same test vectors (ffn-pass/vectors/business/v1.json).

Data that mirrors the TS JSON (registry anchors, observed facts, presentation
input, every result) uses the TS camelCase keys; Python names are snake_case.
"""

from ._version import __version__
from .credential import CredentialError, verify_credential
from .delegation import verify_delegation_chain
from .did import DidResolver
from .dns import doh_resolver, static_txt
from .domain import IdentifierError, normalize_domain, normalize_phone
from .fetch import urllib_fetch
from .networks import FFN_BUSINESS_REGISTRY
from .pin import PinnedRegistryResolver, key_thumbprint, pin_registry_keys
from .presentation import verify_presentation
from .status import StatusChecker
from .verify import VerificationError, lookup_business, verify_business

__all__ = [
    "__version__",
    "FFN_BUSINESS_REGISTRY",
    "CredentialError",
    "DidResolver",
    "IdentifierError",
    "PinnedRegistryResolver",
    "StatusChecker",
    "VerificationError",
    "doh_resolver",
    "key_thumbprint",
    "lookup_business",
    "normalize_domain",
    "normalize_phone",
    "pin_registry_keys",
    "static_txt",
    "urllib_fetch",
    "verify_business",
    "verify_credential",
    "verify_delegation_chain",
    "verify_presentation",
]
