"""Test fixtures: the shared vector file when it can be found, and a small world the
tests sign themselves (keys, DID documents, credentials, status lists, a registry
record), so the rule tests run from an sdist with no vector file.

The vector file is ffn-pass/vectors/business/v1.json in the repository, or the file
named by FFN_VECTORS. Tests that need it skip when neither is there.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import zlib
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from ffn_verify.business import BUSINESS_KINDS, BUSINESS_RECORD_TYP  # noqa: E402

REPO_PASS = Path(__file__).resolve().parents[2]  # ffn-pass/, when the tests run from the repository


def vectors_path() -> Path | None:
    env = os.environ.get("FFN_VECTORS")
    if env:
        return Path(env)
    p = REPO_PASS / "vectors" / "business" / "v1.json"
    return p if p.is_file() else None


def load_world() -> dict | None:
    p = vectors_path()
    return json.loads(p.read_text("utf-8")) if p is not None and p.is_file() else None


NO_VECTORS = ("the shared test vectors are not here: run from the repository "
              "(ffn-pass/vectors/business/v1.json) or set FFN_VECTORS to the file")


# --- JOSE ---------------------------------------------------------------------------

def b64u(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_json(value: Any) -> str:
    return b64u(json.dumps(value, separators=(",", ":")))


class Key:
    """A P-256 key pair."""

    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())
        n = self.private.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")),
                    "y": b64u(n.y.to_bytes(32, "big"))}

    def sign(self, header: dict, payload: dict) -> str:
        signing_input = f"{b64u_json(header)}.{b64u_json(payload)}"
        r, s = decode_dss_signature(self.private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        return f"{signing_input}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    @property
    def did_jwk(self) -> str:
        return "did:jwk:" + b64u(json.dumps({k: self.jwk[k] for k in ("crv", "kty", "x", "y")},
                                            separators=(",", ":")))


def did_document(did: str, keys: dict[str, Key], **extra: Any) -> dict:
    methods = [{"id": f"{did}#{kid}", "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": k.jwk}
               for kid, k in keys.items()]
    refs = [m["id"] for m in methods]
    return {"@context": ["https://www.w3.org/ns/did/v1"], "id": did, "verificationMethod": methods,
            "assertionMethod": refs, "authentication": refs, "capabilityDelegation": refs, **extra}


def sd_jwt(key: Key, kid: str, payload: dict) -> str:
    """An SD-JWT VC with every claim in the clear (no disclosures)."""
    return key.sign({"alg": "ES256", "typ": "dc+sd-jwt", "kid": kid}, {"_sd_alg": "sha-256", **payload}) + "~"


def present(compact: str, holder: Key, *, audience: str, nonce: str, iat: int) -> str:
    """``compact`` with a key-binding JWT from its holder."""
    sd_hash = b64u(hashlib.sha256(compact.encode("ascii")).digest())
    kb = holder.sign({"alg": "ES256", "typ": "kb+jwt"}, {"iat": iat, "aud": audience, "nonce": nonce,
                                                         "sd_hash": sd_hash})
    return compact + kb


def status_list(key: Key, kid: str, *, iss: str, uri: str, values: list[int], iat: int, bits: int = 2) -> str:
    raw = bytearray((len(values) * bits + 7) // 8)
    for i, v in enumerate(values):
        raw[(i * bits) >> 3] |= v << ((i * bits) & 7)
    lst = b64u(zlib.compress(bytes(raw)))
    return key.sign({"alg": "ES256", "typ": "statuslist+jwt", "kid": kid},
                    {"iss": iss, "sub": uri, "iat": iat, "exp": iat + 86_400, "ttl": 3600,
                     "status_list": {"bits": bits, "lst": lst}})


# --- HTTP ---------------------------------------------------------------------------

class Web:
    """A table of URL -> response, as a fetch, with a log of every URL asked for."""

    def __init__(self, routes: dict[str, Any] | None = None):
        self.routes: dict[str, Any] = dict(routes or {})
        self.log: list[str] = []

    def json(self, url: str, value: Any, status: int = 200) -> None:
        self.routes[url] = (status, "application/json", json.dumps(value).encode("utf-8"))

    def text(self, url: str, body: str | bytes, content_type: str = "text/plain", status: int = 200) -> None:
        self.routes[url] = (status, content_type, body.encode("utf-8") if isinstance(body, str) else body)

    def __call__(self, url: str, headers: Any = None) -> tuple[int, str, Any]:
        self.log.append(url)
        hit = self.routes.get(url)
        if hit is None:
            return 404, "text/plain", b"not found"
        if isinstance(hit, Exception):
            raise hit
        return hit() if callable(hit) else hit


def world_fetch(world: dict, extra: dict | None = None):
    """A fetch over the vector file's http table."""
    table = {**world["http"], **(extra or {})}

    def fetch(url: str, headers: Any = None) -> tuple[int, str, bytes]:
        hit = table.get(url)
        if hit is None:
            return 404, "text/plain", b"not found"
        if "error" in hit:
            raise ConnectionError("fetch failed")
        return hit["status"], hit["contentType"], hit["body"].encode("utf-8")

    return fetch


# --- A small registry world -----------------------------------------------------------

NOW = 1_793_000_000
REGISTRY_ORIGIN = "https://registry.test"
REGISTRY_DID = "did:web:registry.test"
STATUS_URI = f"{REGISTRY_ORIGIN}/status/1"


class MiniWorld:
    """One registry and one did:web business, signed here. ``oc_phones`` are the phones
    SPT's official channels attestation confirms; ``record_phones`` those the record lists."""

    def __init__(self, *, domain: str = "biz.example", record_phones: tuple[str, ...] = ("+14155550100",),
                 oc_phones: tuple[str, ...] = ("+14155550100",), profile_phones: tuple[str, ...] | None = None,
                 doc_extra: dict | None = None, status_values: list[int] | None = None):
        self.registry_key = Key()
        self.business_key = Key()
        self.domain = domain
        self.did = f"did:web:{domain}"
        self.registry = {"origin": REGISTRY_ORIGIN, "did": REGISTRY_DID, "name": "Test Registry",
                         "keyThumbprints": [_thumb(self.registry_key.jwk)]}
        self.web = Web()
        self.dns = {f"_ffn.{domain}": [f"v=ffn1; did={self.did}; registry=registry.test"]}
        rk, bk = self.registry_key, self.business_key
        reg_kid, biz_kid = f"{REGISTRY_DID}#records-1", f"{self.did}#key-1"

        self.web.json(f"{REGISTRY_ORIGIN}/.well-known/did.json", did_document(REGISTRY_DID, {"records-1": rk}))
        record_url = f"{REGISTRY_ORIGIN}/v1/businesses/rec-1"
        doc = did_document(self.did, {"key-1": bk}, service=[
            {"id": f"{self.did}#ffn-registry", "type": "FfnVerifiedBusiness", "serviceEndpoint": record_url}])
        doc.update(doc_extra or {})
        self.web.json(f"https://{domain}/.well-known/did.json", doc)
        self.web.text(STATUS_URI, status_list(rk, reg_kid, iss=REGISTRY_DID, uri=STATUS_URI,
                                              values=status_values or [0] * 8, iat=NOW),
                      "application/statuslist+jwt")

        base = {"iat": NOW - 3600, "exp": NOW + 365 * 86_400}
        profile = sd_jwt(bk, biz_kid, {
            "iss": self.did, "sub": self.did, "vct": BUSINESS_KINDS["businessProfile"], **base,
            "cnf": {"jwk": bk.jwk}, "name": "Biz Inc.", "domains": [domain],
            "phones": list(record_phones if profile_phones is None else profile_phones)})
        delegation = sd_jwt(bk, biz_kid, {
            "iss": self.did, "sub": REGISTRY_DID, "vct": BUSINESS_KINDS["delegation"], **base, "jti": "d-1",
            "cnf": {"jwk": rk.jwk}, "scope": ["registry:publish", "registry:serve"], "delegateKind": "registry",
            "status": {"status_list": {"idx": 0, "uri": STATUS_URI}}})
        checks = {"checks": [{"check": "x", "source": "test", "checkedAt": "2026-10-01T00:00:00Z",
                              "result": "pass", "by": "automated"}]}

        def attestation(kind: str, idx: int, claims: dict) -> str:
            return sd_jwt(rk, reg_kid, {"iss": REGISTRY_DID, "sub": self.did, "vct": BUSINESS_KINDS[kind], **base,
                                        "jti": f"a-{idx}", "cnf": {"jwk": bk.jwk}, "evidence": checks,
                                        "status": {"status_list": {"idx": idx, "uri": STATUS_URI}}, **claims})

        self.record_payload = {
            "iss": REGISTRY_DID, "sub": self.did, **base, "recordId": "rec-1", "domains": [domain],
            "phones": list(record_phones), "level": 1, "profile": profile, "delegation": delegation,
            "attestations": [
                attestation("businessIdentity", 1, {"legalName": "Biz Inc.", "entityNumber": "123",
                                                    "jurisdiction": "US-CA", "entityStatus": "active"}),
                attestation("officialChannels", 2, {"domains": [domain], "phones": list(oc_phones)}),
            ],
            "revocations": [], "binding": {"method": "did-web", "checkedAt": "2026-10-01T00:00:00Z"},
            "profileUrl": f"{REGISTRY_ORIGIN}/b/{domain}", "updatedAt": "2026-10-01T00:00:00Z",
        }
        self.publish()

    def publish(self) -> None:
        """Sign the record and serve it for its domains and phones."""
        jwt = self.registry_key.sign({"alg": "ES256", "typ": BUSINESS_RECORD_TYP, "kid": f"{REGISTRY_DID}#records-1"},
                                     self.record_payload)
        for d in self.record_payload["domains"]:
            self.web.text(f"{REGISTRY_ORIGIN}/v1/lookup?domain={d}", jwt, "application/ffn-business-record+jwt")
        for p in self.record_payload["phones"]:
            self.web.text(f"{REGISTRY_ORIGIN}/v1/lookup?phone={p.replace('+', '%2B')}", jwt,
                          "application/ffn-business-record+jwt")


def _thumb(jwk: dict) -> str:
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"))
    return b64u(hashlib.sha256(canonical.encode("utf-8")).digest())
