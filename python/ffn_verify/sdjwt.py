"""SD-JWT verification with key binding, as the TS gets it from @sd-jwt/core 0.22.0.

    <issuer JWT>~<disclosure>~...~[<KB-JWT>]

A disclosure is base64url(JSON [salt, name, value]), or [salt, value] for an array
element. Its digest, base64url(SHA-256(the disclosure string)), must appear in an
``_sd`` array, or as ``{"...": digest}`` in an array. The KB-JWT (typ kb+jwt) is
signed by the cnf key over iat, aud, nonce and sd_hash, the digest of everything up
to and including the ``~`` before it.

The checks run in the library's order and fail with its messages: the TS reads
"expired" off any message that mentions "exp", so the wording is load-bearing.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from ._js import is_num, prop, truthy
from .jose import b64u_decode, b64u_encode, json_parse, sha256, utf8, verify_es256

IANA_HASH_ALGORITHMS = [
    "sha-256", "sha-256-128", "sha-256-120", "sha-256-96", "sha-256-64", "sha-256-32", "sha-384", "sha-512",
    "sha3-224", "sha3-256", "sha3-384", "sha3-512", "blake2s-256", "blake2b-256", "blake2b-512", "k12-256", "k12-512",
]
DEFAULT_SECURE_HASH_ALGORITHMS = [
    "sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512", "blake2s-256", "blake2b-256", "blake2b-512",
    "k12-256", "k12-512",
]
RESERVED_FIELDS = {"_sd", "_sd_alg", "_sd_decoy", "..."}


class SdJwtError(Exception):
    pass


_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def _b64_json(s: str) -> Any:
    """@owf/identity-common base64urlDecodeJson: strict alphabet, strict UTF-8."""
    if not _B64URL.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("Invalid base64url string")
    return json_parse(b64u_decode(s).decode("utf-8"))


@dataclass
class Jwt:
    header: Any
    payload: Any
    signature: str
    encoded: str

    @staticmethod
    def decode(encoded: str) -> Jwt:
        parts = encoded.split(".")
        if len(parts) != 3:
            raise SdJwtError("Invalid JWT as input")
        try:
            return Jwt(_b64_json(parts[0]), _b64_json(parts[1]), parts[2], encoded)
        except Exception:
            raise SdJwtError("Invalid JWT as input") from None

    def unsigned(self) -> str:
        return ".".join(self.encoded.split(".")[:2])


@dataclass
class Disclosure:
    salt: str
    key: str | None  # None for an array element
    value: Any
    digest: str


def _hash(data: str, alg: str) -> bytes:
    # door-core's hasher: SHA-256 is all FFN issues.
    if alg.lower() != "sha-256":
        raise SdJwtError(f"unsupported hash {alg}")
    return sha256(utf8(data))


def _sd_alg(payload: dict) -> str:
    if "_sd_alg" not in payload:
        return "sha-256"
    alg = payload["_sd_alg"]
    if not isinstance(alg, str):
        raise SdJwtError("Invalid _sd_alg: expected string")
    if alg not in IANA_HASH_ALGORITHMS:
        raise SdJwtError(f"Invalid _sd_alg: {alg}")
    if alg not in DEFAULT_SECURE_HASH_ALGORITHMS:
        raise SdJwtError(f"Disallowed _sd_alg: {alg}")
    return alg


def _disclosure(encoded: str, alg: str) -> Disclosure:
    digest = b64u_encode(_hash(encoded, alg))
    try:
        item = _b64_json(encoded)
    except Exception:
        raise SdJwtError("Invalid disclosure data") from None
    if not isinstance(item, list) or len(item) not in (2, 3):
        raise SdJwtError("Invalid disclosure data")
    if not isinstance(item[0], str):
        raise SdJwtError("Invalid disclosure salt")
    if len(item) == 2:
        return Disclosure(item[0], None, item[1], digest)
    if not isinstance(item[1], str):
        raise SdJwtError("Invalid disclosure claim name")
    if item[1] in ("_sd", "..."):
        raise SdJwtError(f'Reserved disclosure claim name "{item[1]}" is not allowed')
    return Disclosure(item[0], item[1], item[2], digest)


def _unpack(value: Any, by_digest: dict[str, Disclosure], seen: set[str], nested: bool) -> Any:
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict) and "..." in item:
                digest = item["..."]
                if len(item) != 1 or not isinstance(digest, str):
                    raise SdJwtError("Invalid array disclosure placeholder")
                if digest in seen:
                    raise SdJwtError("Duplicate digest found in SD-JWT payload")
                seen.add(digest)
                d = by_digest.get(digest)
                if d:
                    if d.key is not None:
                        raise SdJwtError("Object-property disclosure cannot be used as an array element")
                    out.append(_unpack(copy.deepcopy(d.value), by_digest, seen, True))
            elif isinstance(item, (dict, list)):
                out.append(_unpack(item, by_digest, seen, True))
            else:
                out.append(item)
        return out
    if not isinstance(value, dict):
        return value
    for key in list(value):
        if nested and key == "_sd_alg":
            raise SdJwtError("Nested _sd_alg is not allowed")
        if key not in ("_sd", "...") and isinstance(value[key], (dict, list)):
            value[key] = _unpack(value[key], by_digest, seen, True)
    has_sd = "_sd" in value
    sd = value.pop("_sd", None)
    claims: dict[str, Any] = {}
    if has_sd:
        if not isinstance(sd, list) or not all(isinstance(h, str) for h in sd):
            raise SdJwtError("Invalid _sd claim: expected array of strings")
        for digest in sd:
            if digest in seen:
                raise SdJwtError("Duplicate digest found in SD-JWT payload")
            seen.add(digest)
            d = by_digest.get(digest)
            if d:
                if d.key is None:
                    raise SdJwtError("Array disclosure cannot be used as an object property")
                if d.key in value:
                    raise SdJwtError(f'Disclosed claim name "{d.key}" conflicts with existing payload key')
                if d.key in claims:
                    raise SdJwtError(f'Disclosed claim name "{d.key}" conflicts with another disclosure')
                claims[d.key] = _unpack(copy.deepcopy(d.value), by_digest, seen, True)
    value.update(claims)
    return value


def claims_of(payload: dict, disclosures: list[Disclosure]) -> dict:
    """The payload with every disclosure applied (and _sd_alg removed)."""
    by_digest: dict[str, Disclosure] = {}
    for d in disclosures:
        if d.digest in by_digest:
            raise SdJwtError("Duplicate disclosure digest detected")
        by_digest[d.digest] = d
    rest = {k: v for k, v in copy.deepcopy(payload).items() if k != "_sd_alg"}
    seen: set[str] = set()
    claims = _unpack(rest, by_digest, seen, False)
    if any(d not in seen for d in by_digest):
        raise SdJwtError("Unreferenced disclosure(s) detected in SD-JWT")
    return claims


def _check_reserved(node: Any) -> None:
    items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
    for key, value in items:
        if key in RESERVED_FIELDS:
            raise SdJwtError(f'Reserved field name "{key}" is not allowed')
        _check_reserved(value)


def validate_time_claims(payload: dict, now: float, skew: float, name: str = "JWT") -> None:
    """The library's validateJwtPayload: iat and nbf not in the future, exp not passed."""
    skew = skew if truthy(skew) else 0
    times = {}
    for claim in ("iat", "nbf", "exp"):
        if claim in payload:
            if not is_num(payload[claim]):
                raise SdJwtError(f"Verify Error: JWT {claim} must be a number")
            times[claim] = payload[claim]
    if "iat" in times and times["iat"] - skew > now:
        raise SdJwtError(f"Verify Error: {name} is not yet valid")
    if "nbf" in times and times["nbf"] - skew > now:
        raise SdJwtError(f"Verify Error: {name} is not yet valid")
    if "exp" in times and times["exp"] + skew <= now:
        raise SdJwtError(f"Verify Error: {name} is expired")


def _verify_signature(jwt: Jwt, key: Any) -> None:
    if not jwt.signature:
        raise SdJwtError("Verify Error: no signature in JWT")
    if not verify_es256(key, utf8(jwt.unsigned()), b64u_decode(jwt.signature)):
        raise SdJwtError("Verify Error: Invalid JWT Signature")


def _verify_kb(kb: Jwt, cnf_jwk: Any, *, nonce: str, audience: str | None, max_age: float, now: float,
               skew: float) -> dict:
    if not truthy(kb.header) or not truthy(kb.payload) or not kb.signature:
        raise SdJwtError("Verify Error: Invalid JWT")
    h, p = kb.header, kb.payload
    alg, typ = prop(h, "alg"), prop(h, "typ")
    iat, aud, kb_nonce, sd_hash = prop(p, "iat"), prop(p, "aud"), prop(p, "nonce"), prop(p, "sd_hash")
    if (not isinstance(alg, str) or alg == "none" or typ != "kb+jwt" or not is_num(iat) or not isinstance(aud, str)
            or not isinstance(kb_nonce, str) or not isinstance(sd_hash, str) or not sd_hash):
        raise SdJwtError("Invalid Key Binding Jwt")
    if alg != "ES256":
        raise SdJwtError(f"Verify Error: Disallowed Key Binding alg {alg}")
    if kb_nonce != nonce:
        raise SdJwtError("Verify Error: Invalid Nonce")
    if audience is not None and aud != audience:
        raise SdJwtError("Verify Error: Invalid Key Binding audience")
    if iat + max_age + skew < now:
        raise SdJwtError("Verify Error: Key Binding JWT is too old")
    validate_time_claims(p, now, skew, "Key Binding JWT")
    _verify_signature(kb, cnf_jwk)
    return p


def verify(compact: str, *, issuer_key: Any, cnf_jwk: Any, now: float, skew: float,
           key_binding: dict | None = None) -> tuple[dict, dict | None]:
    """Issuer signature, disclosures, time claims and (when asked) the KB-JWT.
    Returns (claims, KB-JWT payload or None)."""
    parts = compact.split("~")
    if len(parts) == 1:
        raise SdJwtError("Invalid SD-JWT: missing SD-JWT separator")
    jwt = Jwt.decode(parts[0])
    if not truthy(jwt.payload):
        raise SdJwtError("Payload is undefined on the JWT. Invalid state reached")
    kb = Jwt.decode(parts[-1]) if parts[-1] else None
    alg = _sd_alg(jwt.payload)
    disclosures = [_disclosure(d, alg) for d in parts[1:-1]]

    header_alg = prop(jwt.header, "alg") if jwt.header is not None else None
    if not isinstance(header_alg, str) or header_alg == "none":
        raise SdJwtError('Verify Error: alg "none" is not allowed')
    if header_alg != "ES256":
        raise SdJwtError(f"Verify Error: Disallowed alg {header_alg}")
    _verify_signature(jwt, issuer_key)
    claims = claims_of(jwt.payload, disclosures)
    _check_reserved(claims)
    validate_time_claims(claims, now, skew)

    if not key_binding or not truthy(key_binding.get("nonce")):
        return claims, None
    if kb is None:
        raise SdJwtError("Key Binding JWT not exist")
    kb_payload = _verify_kb(kb, cnf_jwk, nonce=key_binding["nonce"], audience=key_binding.get("audience"),
                            max_age=key_binding["maxAgeSeconds"], now=now, skew=skew)
    presented = compact[: compact.rindex("~") + 1]
    if b64u_encode(_hash(presented, alg)) != kb_payload["sd_hash"]:
        raise SdJwtError("Invalid sd_hash in Key Binding JWT")
    return claims, kb_payload
