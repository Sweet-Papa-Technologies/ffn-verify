"""The few JavaScript semantics the TypeScript verifier leans on.

The verifier reads JSON from untrusted hosts. Where the TS code relies on a JS
behaviour that Python doesn't share (truthiness of ``{}`` and ``[]``,
``String(x)`` in a template literal, ``obj.key`` on ``null`` throwing), these
helpers reproduce it, so odd input fails or passes the same way in both.

JSON ``null`` and a missing key both read as ``None`` here. Where the TS code
tells them apart (``x !== undefined``), the caller checks ``key in obj``.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

# JS WhiteSpace and LineTerminator: what String.prototype.trim() strips and \s matches.
JS_WHITESPACE = (
    "\t\n\v\f\r           "
    "       　﻿"
)
JS_WS_CLASS = "[" + "".join(f"\\u{ord(c):04x}" for c in JS_WHITESPACE) + "]"


def trim(s: str) -> str:
    return s.strip(JS_WHITESPACE)


def is_num(v: Any) -> bool:
    """typeof v === 'number' (JSON never yields NaN or Infinity)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def truthy(v: Any) -> bool:
    if v is None or v is False:
        return False
    if is_num(v):
        return v != 0 and not (isinstance(v, float) and math.isnan(v))
    if isinstance(v, str):
        return v != ""
    return True  # objects and arrays, even empty ones


def prop(obj: Any, key: str) -> Any:
    """obj.key: throws on null/undefined, undefined on anything that isn't an object."""
    if obj is None:
        raise TypeError(f"Cannot read properties of null (reading '{key}')")
    return obj.get(key) if isinstance(obj, dict) else None


def opt(obj: Any, key: str) -> Any:
    """obj?.key"""
    return None if obj is None else prop(obj, key)


def array(v: Any, what: str = "value") -> list:
    """What .map/.filter/.some on a non-array would throw for."""
    if not isinstance(v, list):
        raise TypeError(f"{what} is not an array")
    return v


def iterable(v: Any, what: str = "value") -> list:
    """for...of and spread: arrays, and strings by code point."""
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return list(v)
    raise TypeError(f"{what} is not iterable")


def same(a: Any, b: Any) -> bool:
    """SameValueZero for JSON values (no bool/number mixing, 2 == 2.0)."""
    if is_num(a) and is_num(b):
        return a == b
    return type(a) is type(b) and a == b


def includes(container: Any, item: Any) -> bool:
    """Array.prototype.includes, or String.prototype.includes when it's a string."""
    if isinstance(container, list):
        return any(same(x, item) for x in container)
    if isinstance(container, str):
        return js_str(item) in container
    raise TypeError("includes is not a function")


def js_str(v: Any) -> str:
    """String(v), as a template literal renders it."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    if isinstance(v, list):
        return ",".join("" if x is None else js_str(x) for x in v)
    return "[object Object]"


def template(obj: Any, key: str) -> str:
    """`${obj.key}`: a missing member renders as "undefined", null as "null"."""
    prop(obj, key)  # null throws
    return js_str(obj[key]) if isinstance(obj, dict) and key in obj else "undefined"


def nullish(v: Any, default: Any) -> Any:
    """v ?? default"""
    return default if v is None else v


def join(values: list, sep: str) -> str:
    """Array.prototype.join: null and undefined become empty strings."""
    return sep.join("" if v is None else js_str(v) for v in values)


def utf16_key(v: Any) -> bytes:
    """Sort key matching Array.prototype.sort()'s default (UTF-16 code units of String(v))."""
    return js_str(v).encode("utf-16-be", "surrogatepass")


def iso(seconds: float) -> str:
    """new Date(seconds * 1000).toISOString()"""
    ms = int(seconds * 1000)  # Date truncates toward zero
    dt = datetime.fromtimestamp(ms // 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms % 1000:03d}Z"
