"""Verifying an SD-JWT VC outside the OpenID4VC flows, as door-core's credential.ts:
a business's own profile, SPT's attestations for the registry, an agent presenting
a delegation over plain HTTP. No wallet or trust registry needed to check one.
"""

from __future__ import annotations

import re
import time
from typing import Any

from . import sdjwt
from ._js import is_num, opt, prop, truthy
from .did import DidResolver
from .jose import b64u_encode, decode_jwt, header_kid, jwk_thumbprint, sha256


class CredentialError(Exception):
    def __init__(self, message: str, code: str = "invalid_credential"):
        super().__init__(message)
        self.code = code
        self.message = message


def issuer_jwt_of(compact: str) -> str:
    """Issuer-signed part of a compact SD-JWT (everything before the first '~')."""
    return compact.split("~")[0]


def credential_hash(compact: str) -> str:
    """Base64url SHA-256 of the issuer-signed JWT: how a child delegation names its parent."""
    return b64u_encode(sha256(issuer_jwt_of(compact)))


def same_key(a: Any, b: Any) -> bool:
    """Same key? Thumbprints, so member order and extra members don't matter."""
    return jwk_thumbprint(a) == jwk_thumbprint(b)


def verify_credential(compact: str, *, resolver: DidResolver, now: float | None = None, skew_seconds: float = 60,
                      key_binding: dict | None = None) -> dict:
    """Verify the issuer signature (key from the issuer's DID document), every disclosure,
    the time claims and, when ``key_binding`` ({nonce, audience, maxAgeSeconds}) is given,
    the holder's key binding. Status is separate (see StatusChecker) because callers treat
    an unreachable status list differently.

    Returns {header, claims, iss, vct, cnfJwk, issuerKey, kb?}. Raises CredentialError.
    """
    try:
        header, payload, _, _ = decode_jwt(issuer_jwt_of(compact))
    except Exception:
        raise CredentialError("malformed credential") from None
    iss, vct = prop(payload, "iss"), prop(payload, "vct")
    if not isinstance(iss, str) or not isinstance(vct, str):
        raise CredentialError("credential has no issuer or type")
    if prop(header, "alg") != "ES256":
        raise CredentialError("unsupported alg")
    cnf_jwk = opt(prop(payload, "cnf"), "jwk")
    if not truthy(cnf_jwk):
        raise CredentialError("credential is not key-bound")

    try:
        issuer_key = resolver.assertion_key(iss, header_kid(header))
    except Exception as err:
        raise CredentialError(f"issuer key not found: {err}", "untrusted_issuer") from None

    now = int(time.time()) if now is None else now
    skew = skew_seconds
    kb_options = None
    if key_binding is not None:
        max_age = key_binding.get("maxAgeSeconds")
        kb_options = {**key_binding, "maxAgeSeconds": 300 if max_age is None else max_age}
    try:
        claims, kb_payload = sdjwt.verify(compact, issuer_key=issuer_key, cnf_jwk=cnf_jwk, now=now, skew=skew,
                                          key_binding=kb_options)
    except Exception as err:
        message = str(err)
        code = "expired" if re.search(r"\bis expired\b", message, re.ASCII) else "invalid_credential"
        raise CredentialError(f"credential failed verification: {message}", code) from None
    # Belt and braces on time: the library's checks read the disclosed claims.
    exp, nbf = payload.get("exp"), payload.get("nbf")
    if is_num(exp) and now - skew > exp:
        raise CredentialError("credential expired", "expired")
    if is_num(nbf) and now + skew < nbf:
        raise CredentialError("credential not yet valid")

    result = {"header": header, "claims": claims, "iss": iss, "vct": vct, "cnfJwk": cnf_jwk, "issuerKey": issuer_key}
    if kb_options is not None:
        if kb_payload is None:
            raise CredentialError("key binding missing")
        if kb_payload.get("aud") != kb_options.get("audience"):
            raise CredentialError("key binding audience mismatch")
        if kb_payload.get("nonce") != kb_options.get("nonce"):
            raise CredentialError("key binding nonce mismatch")
        iat = kb_payload.get("iat")
        age = now - (0 if iat is None else iat)
        if age > kb_options["maxAgeSeconds"] + skew or age < -skew:
            raise CredentialError("key binding is stale")
        result["kb"] = {"aud": kb_payload["aud"], "nonce": kb_payload["nonce"], "iat": iat}
    return result
