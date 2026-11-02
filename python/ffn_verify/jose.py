"""Minimal ES256 JOSE, as door-core's jose.ts.

ES256 only: it is the HAIP / EUDI baseline and what every FFN key signs with.
Signatures are the raw 64-byte r||s form JWS uses, not DER.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ._js import is_num, prop


class JoseError(Exception):
    pass


def utf8(s: str) -> bytes:
    """TextEncoder: lone surrogates become U+FFFD instead of raising."""
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_ASCII_WS = re.compile(r"[\t\n\f\r ]")
_B64 = re.compile(r"[A-Za-z0-9+/]*")


def b64u_decode(value: str) -> bytes:
    """door-core's b64uDecode: pad, map to base64, then atob's forgiving decode."""
    if not isinstance(value, str):
        raise JoseError("Invalid character")
    pad = "" if len(value) % 4 == 0 else "=" * (4 - len(value) % 4)
    s = _ASCII_WS.sub("", value.replace("-", "+").replace("_", "/") + pad)
    if len(s) % 4 == 0:
        s = s[:-2] if s.endswith("==") else s[:-1] if s.endswith("=") else s
    if len(s) % 4 == 1 or not _B64.fullmatch(s):
        raise JoseError("Invalid character")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _no_constants(name: str) -> Any:
    raise ValueError(f"Unexpected token {name}")  # JSON.parse has no NaN or Infinity


def json_parse(text: str) -> Any:
    return json.loads(text, parse_constant=_no_constants)


def b64u_decode_json(value: str) -> Any:
    # TextDecoder(): invalid UTF-8 becomes U+FFFD and a leading BOM is dropped.
    text = b64u_decode(value).decode("utf-8", "replace")
    return json_parse(text[1:] if text.startswith("﻿") else text)


def sha256(data: bytes | str) -> bytes:
    return hashlib.sha256(utf8(data) if isinstance(data, str) else data).digest()


def decode_jwt(jwt: str) -> tuple[Any, Any, str, bytes]:
    """(header, payload, signing input, signature). Nothing is verified."""
    parts = jwt.split(".") if isinstance(jwt, str) else []
    if len(parts) != 3:
        raise JoseError("malformed JWT")
    h, p, s = parts
    try:
        return b64u_decode_json(h), b64u_decode_json(p), f"{h}.{p}", b64u_decode(s)
    except Exception:
        raise JoseError("malformed JWT") from None


def header_kid(header: Any) -> str | None:
    """The JWS kid, or None when absent. A kid that isn't a string (even null) breaks
    key lookup in the TS too, where kid.startsWith throws."""
    if not isinstance(header, dict) or "kid" not in header:
        prop(header, "kid")  # null header throws, as in the TS
        return None
    kid = header["kid"]
    if kid is None:
        raise TypeError("Cannot read properties of null (reading 'startsWith')")
    if not isinstance(kid, str):
        raise TypeError("kid.startsWith is not a function")
    return kid


def _p256_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    """WebCrypto importKey('jwk'): x and y must be 32-byte coordinates of a point on P-256."""
    try:
        x, y = b64u_decode(jwk.get("x")), b64u_decode(jwk.get("y"))
        if len(x) != 32 or len(y) != 32:
            raise ValueError
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    except Exception:
        raise JoseError("Invalid keyData") from None


def verify_es256(public_jwk: Any, data: bytes, signature: bytes) -> bool:
    if prop(public_jwk, "kty") != "EC" or prop(public_jwk, "crv") != "P-256":
        return False
    if len(signature) != 64:
        return False
    key = _p256_key(public_jwk)  # a malformed key throws, as importKey does
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def jwk_thumbprint(jwk: Any) -> str:
    """RFC 7638 thumbprint (EC keys), base64url. Members the key lacks are left out, as
    JSON.stringify drops undefined."""
    if prop(jwk, "kty") != "EC":
        raise JoseError("only EC keys are supported")
    canonical = {k: jwk[k] for k in ("crv", "kty", "x", "y") if k in jwk}
    return b64u_encode(sha256(json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)))


def verify_jwt(jwt: str, public_jwk: Any, *, typ: str | None = None, now: float, skew: float = 60,
               audience: str | None = None) -> tuple[Any, Any]:
    """Signature and the standard time claims. Raises JoseError on any failure."""
    header, payload, signing_input, signature = decode_jwt(jwt)
    if prop(header, "alg") != "ES256":
        raise JoseError("unsupported alg")
    if typ and prop(header, "typ") != typ:
        raise JoseError(f"expected typ {typ}")
    if not verify_es256(public_jwk, utf8(signing_input), signature):
        raise JoseError("bad signature")
    exp, nbf, aud = prop(payload, "exp"), prop(payload, "nbf"), prop(payload, "aud")
    if is_num(exp) and now - skew > exp:
        raise JoseError("expired")
    if is_num(nbf) and now + skew < nbf:
        raise JoseError("not yet valid")
    if audience is not None:
        auds = aud if isinstance(aud, list) else [aud]
        if audience not in auds:
            raise JoseError("wrong audience")
    return header, payload
