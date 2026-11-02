"""Verifying a key-bound presentation someone handed you, with the nonce and audience
you gave them, as verify-business's presentation.ts: the check behind the headless
door and the MCP server's verify_presentation tool. Delegations are walked to their
root; anything else must come from an issuer the caller accepts.

Trust is decided before anything is fetched: a credential from an issuer the caller
doesn't accept, or a delegation chain rooted at a DID the caller doesn't accept, fails
without a single network request.
"""

from __future__ import annotations

import time
from typing import Any, MutableMapping

from ._js import includes, iterable, nullish, truthy
from .business import BUSINESS_KINDS
from .credential import CredentialError, issuer_jwt_of, same_key, verify_credential
from .delegation import check_chain_root, verify_delegation_chain
from .did import DidResolver, is_did_jwk, jwk_of_did_jwk
from .fetch import DEFAULT_TIMEOUT, Fetch, urllib_fetch
from .jose import decode_jwt
from .pin import anchored_resolver, pin_known_registries
from .status import StatusChecker

_STRUCTURAL = {"iss", "iat", "exp", "sub", "jti", "vct", "cnf", "status", "_sd_alg"}


def _peek(presentation: Any) -> tuple[str, str] | None:
    """(iss, vct) as the credential states them, unverified; None when it can't be read
    (verify_credential then reports why)."""
    try:
        payload = decode_jwt(issuer_jwt_of(presentation))[1]
    except Exception:
        return None
    iss, vct = (payload.get("iss"), payload.get("vct")) if isinstance(payload, dict) else (None, None)
    return (iss, vct) if isinstance(iss, str) and isinstance(vct, str) else None


def verify_presentation(input: dict, *, fetch: Fetch | None = None, resolver: DidResolver | None = None,
                        store: MutableMapping[str, dict] | None = None, now: float | None = None,
                        registry: dict | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """``input`` is {presentation, chain?, nonce, audience, roots?, requiredScope?, issuers?,
    maxAgeSeconds?}: chain holds the parent delegations, nearest first; roots are the DIDs
    a delegation chain may start at; issuers are accepted for anything else.

    ``registry`` ({origin, did?, keyThumbprints?}, e.g. FFN_BUSINESS_REGISTRY) pins that
    registry's keys, as verify_business does; it doesn't add the registry to ``issuers``.
    The known FFN registries are pinned with or without it. ``timeout`` is the total
    time limit, in seconds, for each request.

    Returns {verified: True, subject, vct, issuer, claims, delegation?} or
    {verified: False, code, message}.
    """
    fetch = fetch or urllib_fetch
    base = resolver or DidResolver(fetch=fetch, timeout=timeout)
    resolver = anchored_resolver(base, registry) if registry is not None else pin_known_registries(base)
    now_sec = int(time.time()) if now is None else now
    status = StatusChecker(resolver=resolver, fetch=fetch, store=store, now=lambda: now_sec, timeout=timeout)
    key_binding = {"nonce": input.get("nonce"), "audience": input.get("audience"),
                   "maxAgeSeconds": nullish(input.get("maxAgeSeconds"), 300)}
    try:
        # Trust first: nothing is resolved or fetched for an issuer or root the caller doesn't accept.
        peek = _peek(input.get("presentation"))
        if peek is not None:
            iss, vct = peek
            if vct == BUSINESS_KINDS["delegation"]:
                _require_roots(input.get("roots"))
                check_chain_root([input["presentation"], *iterable(nullish(input.get("chain"), []), "chain")],
                                 input["roots"])
            else:
                _require_issuer(input.get("issuers"), iss)

        v = verify_credential(input.get("presentation"), resolver=resolver, key_binding=key_binding, now=now_sec)
        subject = v["claims"].get("sub")
        if not isinstance(subject, str):
            raise CredentialError("credential has no subject")
        claims = {k: value for k, value in v["claims"].items() if k not in _STRUCTURAL}
        if v["vct"] == BUSINESS_KINDS["delegation"]:
            roots: Any = input.get("roots")
            _require_roots(roots)
            required = input.get("requiredScope")
            delegation = verify_delegation_chain(
                [input["presentation"], *iterable(nullish(input.get("chain"), []), "chain")],
                resolver=resolver, status=status, now=now_sec, roots=roots, key_binding=key_binding,
                required_scope=required if truthy(required) else None)
            return {"verified": True, "subject": subject, "vct": v["vct"], "issuer": v["iss"], "claims": claims,
                    "delegation": delegation}
        _require_issuer(input.get("issuers"), v["iss"])
        if is_did_jwk(subject):
            holds = same_key(jwk_of_did_jwk(subject), v["cnfJwk"])
        else:
            holds = resolver.controls_key(subject, v["cnfJwk"])
        if not holds:
            raise CredentialError(f"{subject} does not list the presenting key", "wrong_holder")
        if truthy(v["claims"].get("status")):
            outcome = status.check(v["claims"]["status"], v["iss"])
            if outcome["status"] != "valid":
                raise CredentialError(f"credential status is {outcome['status']}",
                                      "status_unknown" if outcome["status"] == "unknown" else "revoked")
        return {"verified": True, "subject": subject, "vct": v["vct"], "issuer": v["iss"], "claims": claims}
    except CredentialError as err:
        return {"verified": False, "code": err.code, "message": err.message}
    except Exception as err:
        return {"verified": False, "code": "invalid_presentation", "message": str(err)}


def _require_roots(roots: Any) -> None:
    if not truthy(len(roots) if isinstance(roots, (list, str)) else None):
        raise CredentialError("no accepted roots given for a delegation", "untrusted_root")


def _require_issuer(issuers: Any, iss: str) -> None:
    if issuers is None or not includes(issuers, iss):
        raise CredentialError(f"issuer {iss} is not accepted", "untrusted_issuer")
