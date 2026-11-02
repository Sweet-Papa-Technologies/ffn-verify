"""Delegation chains, as door-core's delegation.ts.

A delegation is a credential the delegator signs: this DID may do these things for
me, until this date, and I can revoke it. A delegate can pass on part of what it
holds; the verifier walks the chain back to the root.
"""

from __future__ import annotations

from typing import Any

from ._js import array, includes, is_num, iso, join, js_str, same, utf16_key
from .business import BUSINESS_KINDS
from .credential import CredentialError, credential_hash, issuer_jwt_of, same_key, verify_credential
from .did import DidResolver, is_did_jwk, jwk_of_did_jwk
from .jose import decode_jwt
from .status import StatusChecker

MAX_CHAIN_DEPTH = 5


def scope_covers(held: Any, wanted: Any) -> bool:
    """Does held cover wanted? Exact match, or a "prefix:*" wildcard."""
    for h in array(held, "scope"):
        if same(h, wanted):
            return True
        if isinstance(h, str) and h.endswith(":*"):
            if not isinstance(wanted, str):
                raise TypeError("wanted.startsWith is not a function")
            if wanted.startswith(h[:-1]):
                return True
        elif not isinstance(h, str):
            raise TypeError("h.endsWith is not a function")
    return False


def check_chain_root(chain: list[Any], roots: Any) -> None:
    """Trust before fetching: decode the chain (nothing verified, nothing fetched) and
    refuse it unless its root link (the last) is issued by one of ``roots``.
    Raises CredentialError."""
    payloads = []
    for compact in chain:
        try:
            payloads.append(decode_jwt(issuer_jwt_of(compact))[1])
        except Exception:
            raise CredentialError("malformed credential") from None
    root = payloads[-1].get("iss") if isinstance(payloads[-1], dict) else None
    if not (isinstance(root, str) and includes(roots, root)):
        raise CredentialError(f"the chain starts at {js_str(root)}, which this verifier doesn't accept",
                              "untrusted_root")


def verify_delegation_chain(chain: list[str], *, resolver: DidResolver, status: StatusChecker,
                            now: float | None = None, roots: list[str] | None = None,
                            required_scope: list[str] | None = None, allow_unknown_status: bool = False,
                            key_binding: dict | None = None) -> dict:
    """Verify a chain of delegations, leaf first: chain[0] names the presenter,
    chain[-1] is signed by the root. Each link must be signed by the key its parent
    delegated to, stay inside its parent's scope and expiry, name its parent by hash,
    and be unrevoked. With ``roots``, a chain whose root link isn't issued by one of
    them fails before anything is fetched; a link's status list is fetched only after
    every link's signature has verified.

    Returns {root, delegate, delegateKind, scope, expiresAt, links}. Raises CredentialError.
    """
    if len(chain) == 0:
        raise CredentialError("empty delegation chain", "broken_chain")
    if len(chain) > MAX_CHAIN_DEPTH:
        raise CredentialError("delegation chain is too long", "broken_chain")
    # The root is decided before any DID is resolved or status list fetched.
    if roots is not None:
        check_chain_root(chain, roots)

    verified = []
    for i, compact in enumerate(chain):
        v = verify_credential(compact, resolver=resolver, now=now,
                              key_binding=key_binding if i == 0 else None)
        if v["vct"] != BUSINESS_KINDS["delegation"]:
            raise CredentialError(f"link {i} is not a delegation", "broken_chain")
        verified.append({**v, "compact": compact})

    links = []
    for i, v in enumerate(verified):
        c = v["claims"]
        sub = c.get("sub")
        if not isinstance(sub, str):
            raise CredentialError(f"link {i} has no delegate", "broken_chain")
        if not isinstance(c.get("scope"), list) or len(c["scope"]) == 0:
            raise CredentialError(f"link {i} has no scope", "broken_chain")
        if not is_num(c.get("exp")):
            raise CredentialError(f"link {i} never expires", "broken_chain")

        # The delegate's DID must control the key the delegation is bound to.
        if is_did_jwk(sub):
            if not same_key(jwk_of_did_jwk(sub), v["cnfJwk"]):
                raise CredentialError(f"link {i} is bound to a key {sub} doesn't hold", "broken_chain")
        elif not resolver.controls_key(sub, v["cnfJwk"]):
            raise CredentialError(f"link {i} is bound to a key {sub} doesn't list", "broken_chain")

        if i + 1 < len(verified):
            parent = verified[i + 1]
            p = parent["claims"]
            if v["iss"] != p.get("sub"):
                raise CredentialError(f"link {i} is signed by {v['iss']}, not the delegate above it", "broken_chain")
            if not same_key(v["issuerKey"], parent["cnfJwk"]):
                raise CredentialError(f"link {i} is signed by a key the parent didn't delegate to", "broken_chain")
            if c.get("parent") != credential_hash(parent["compact"]):
                raise CredentialError(f"link {i} names a different parent", "broken_chain")
            beyond = [s for s in c["scope"] if not scope_covers(p.get("scope"), s)]
            if beyond:
                raise CredentialError(f"link {i} widens the scope ({join(beyond, ', ')})", "broken_chain")
            # The parent's own exp is checked on its turn; a non-number compares false in JS.
            if is_num(p.get("exp")) and c["exp"] > p["exp"]:
                raise CredentialError(f"link {i} outlives its parent", "broken_chain")
        elif "parent" in c:
            raise CredentialError("the chain is missing its root", "broken_chain")

        link_status = "valid"
        if "status" in c:
            outcome = status.check(c["status"], v["iss"])
            if outcome["status"] in ("invalid", "suspended"):
                raise CredentialError(f"link {i} has been revoked", "revoked")
            if outcome["status"] == "unknown":
                if not allow_unknown_status:
                    raise CredentialError(f"link {i} status could not be checked", "status_unknown")
                link_status = "unknown"
        link = {"jti": c["jti"]} if isinstance(c.get("jti"), str) else {}
        links.append({
            **link,
            "iss": v["iss"],
            "sub": sub,
            "scope": c["scope"],
            "delegateKind": c.get("delegateKind") if c.get("delegateKind") is not None else "agent",
            "expiresAt": iso(c["exp"]),
            "status": link_status,
        })

    root = links[-1]["iss"]
    if roots is not None and not includes(roots, root):
        raise CredentialError(f"the chain starts at {root}, which this verifier doesn't accept", "untrusted_root")
    leaf = links[0]
    for wanted in required_scope or []:
        if not scope_covers(leaf["scope"], wanted):
            raise CredentialError(f"the delegation doesn't cover {wanted}", "insufficient_scope")
    return {
        "root": root,
        "delegate": leaf["sub"],
        "delegateKind": leaf["delegateKind"],
        "scope": leaf["scope"],
        "expiresAt": sorted((link["expiresAt"] for link in links), key=utf16_key)[0],
        "links": links,
    }
