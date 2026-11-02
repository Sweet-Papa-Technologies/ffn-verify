"""Domain binding records, as door-core's binding.ts.

The registry lists the business's official domains, and each domain points back:

    https://<domain>/.well-known/did.json   the business DID document, with a service
                                             entry naming its registry record
    _ffn.<domain>  TXT  "v=ffn1; did=<did>; registry=<registry host>"

A lookalike domain fails both directions. Verifiers trust the registry they already
know, never what the page says.
"""

from __future__ import annotations

import re
from typing import Any

from ._js import JS_WS_CLASS, prop, trim

FFN_SERVICE_TYPE = "FfnVerifiedBusiness"
FFN_TXT_PREFIX = "_ffn"


def registry_entries_of(doc: dict) -> list[str]:
    """Registry record URLs the DID document points at (service entries of type FfnVerifiedBusiness).
    A ``service`` that isn't an array, and entries that aren't objects, point nowhere."""
    out: list[str] = []
    services = doc.get("service")
    if not isinstance(services, list):
        return out
    for s in services:
        if not isinstance(s, dict):
            continue
        types = prop(s, "type")
        types = types if isinstance(types, list) else [types]
        if FFN_SERVICE_TYPE not in [t for t in types if isinstance(t, str)]:
            continue
        ends = prop(s, "serviceEndpoint")
        for e in ends if isinstance(ends, list) else [ends]:
            if isinstance(e, str):
                out.append(e)
    return out


def ffn_txt_name(domain: str) -> str:
    return f"{FFN_TXT_PREFIX}.{domain}"


_SPLIT_QUOTES = re.compile('"' + JS_WS_CLASS + '*"')


def unquote_txt(value: str) -> str:
    # DNS answers may arrive quoted or split into 255-byte strings.
    return re.sub(r'^"|"\Z', "", _SPLIT_QUOTES.sub("", value))


def parse_ffn_txt(value: Any) -> dict | None:
    """{v, did, registry} from a _ffn TXT value, or None when it isn't one."""
    if not isinstance(value, str):
        raise TypeError("value.replace is not a function")
    fields = {}
    for part in unquote_txt(value).split(";"):
        kv = trim(part).split("=")
        if len(kv) >= 2:
            fields[trim(kv[0])] = trim("=".join(kv[1:]))
    if fields.get("v") != "ffn1" or not fields.get("did") or not fields.get("registry"):
        return None
    return {"v": "ffn1", "did": fields["did"], "registry": fields["registry"]}
