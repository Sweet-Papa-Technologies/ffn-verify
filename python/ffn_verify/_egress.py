"""Which URLs the verifier fetches on someone else's say-so.

A status list URI and a did:web come from credentials and records, so a hostile one
could point the verifier at the network it runs in. Before any request to such a URL:

* it must be ``https:``;
* its host must not be an IP literal in a private, loopback, link-local, CGNAT,
  multicast, unspecified or reserved range (IPv4 or IPv6, IPv4-mapped included), nor
  ``localhost``, ``*.localhost``, ``*.local``, ``*.internal`` or a single-label name
  (``metadata``, ``printer``), which resolves through the local search domains.

This checks the URL, not where its name resolves: a public name whose DNS answers with
a private address (DNS rebinding) passes. Run the verifier behind an egress proxy
that refuses private destinations if that matters where it runs.

The host is read with the WHATWG parser (as the TS verifier and browsers read it).
Python's own HTTP stack splits URLs differently in a few places (``\\``, ``@`` and
non-ASCII in the authority), so a URL whose authority holds any of those is refused
rather than fetched under two readings.
"""

from __future__ import annotations

import ipaddress
import re

from .url import URL, URLError


class RefusedURL(ValueError):
    """The URL is not one the verifier fetches. No request was made."""


_V4_REFUSED = tuple(ipaddress.IPv4Network(n) for n in (
    "0.0.0.0/8",  # "this network", unspecified
    "10.0.0.0/8",  # private
    "100.64.0.0/10",  # CGNAT shared address space
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link-local
    "172.16.0.0/12",  # private
    "192.0.0.0/24",  # IETF protocol assignments
    "192.0.2.0/24",  # documentation
    "192.88.99.0/24",  # 6to4 relay anycast (deprecated)
    "192.168.0.0/16",  # private
    "198.18.0.0/15",  # benchmarking
    "198.51.100.0/24",  # documentation
    "203.0.113.0/24",  # documentation
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved, and the broadcast address
))
# IPv6: only global unicast (2000::/3) is ever public; inside it, these are not.
_V6_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")
_V6_REFUSED_IN_GLOBAL = tuple(ipaddress.IPv6Network(n) for n in (
    "2001::/23",  # IETF protocol assignments (Teredo, benchmarking, ORCHID)
    "2001:db8::/32",  # documentation
    "3fff::/20",  # documentation
    "2002::/16",  # 6to4
))
_V6_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")  # well-known prefix: the low 32 bits are an IPv4 address

_LOCAL_NAMES = ("localhost",)
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal")


def refused_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Is this address one the verifier never fetches from?"""
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in n for n in _V4_REFUSED)
    if ip.ipv4_mapped is not None:
        return refused_ip(ip.ipv4_mapped)
    if ip in _V6_NAT64:
        return refused_ip(ipaddress.IPv4Address(int(ip) & 0xFFFF_FFFF))
    if ip not in _V6_GLOBAL_UNICAST:
        return True  # unspecified, loopback, mapped/compatible, ULA, link-local, multicast, reserved
    return any(ip in n for n in _V6_REFUSED_IN_GLOBAL)


def _ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a WHATWG-parsed hostname names, or None for a domain name."""
    if hostname.startswith("[") and hostname.endswith("]"):
        return ipaddress.IPv6Address(hostname[1:-1])
    if re.fullmatch(r"[0-9]+(\.[0-9]+){3}", hostname):
        return ipaddress.IPv4Address(hostname)  # the parser has already normalized every IPv4 form
    return None


def _name(hostname: str) -> str:
    return hostname.lower().rstrip(".")


def refused_host(hostname: str) -> bool:
    """A WHATWG ``URL.hostname`` the verifier never fetches from."""
    ip = _ip_literal(hostname)
    if ip is not None:
        return refused_ip(ip)
    name = _name(hostname)
    if name in _LOCAL_NAMES or name.endswith(_LOCAL_SUFFIXES):
        return True
    # A single label (metadata, printer) resolves through the local search domains,
    # i.e. inside the network the verifier runs in.
    return "." not in name


def is_loopback_host(hostname: str) -> bool:
    """127.0.0.0/8, ::1 (or IPv4-mapped loopback), ``localhost`` or ``*.localhost``:
    where plain http is allowed, for a registry under local test."""
    try:
        ip = _ip_literal(hostname)
    except ValueError:
        return False
    if ip is None:
        name = _name(hostname)
        return name == "localhost" or name.endswith(".localhost")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


_UNSAFE_IN_AUTHORITY = re.compile(r"[^\x21-\x7e]|[@\\]")


def check_public_https(url: str, what: str = "URL") -> URL:
    """Raise RefusedURL unless ``url`` is an https URL on a public host (see the module doc)."""
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RefusedURL(f"{what} must be https")
    if re.search(r"[\x00-\x20\x7f]", url):
        raise RefusedURL(f"{what} is not a plain URL")
    _check_authority(url, what)
    try:
        parsed = URL(url)
    except (URLError, ValueError):
        raise RefusedURL(f"{what} is not a valid URL") from None
    try:
        refused = refused_host(parsed.hostname)
    except ValueError:
        refused = True
    if refused:
        raise RefusedURL(f"{what} points at a private or local host")
    return parsed


def _check_authority(url: str, what: str) -> None:
    """The authority as written, before any parser normalizes it (up to the first / ? or
    #): empty, or holding @, \\, whitespace, a control character or non-ASCII, it could
    be read two ways."""
    m = re.match(r"[A-Za-z][A-Za-z0-9+.\-]*://([^/?#]*)", url)
    if not m or not m.group(1) or _UNSAFE_IN_AUTHORITY.search(m.group(1)):
        raise RefusedURL(f"{what} is not a plain URL")


def check_registry_origin(origin: str) -> URL:
    """The registry origin a caller pins: https, or http on a loopback host
    (``localhost`` included) for local tests. The caller chooses it, so unlike the
    hosts a record or presentation names, a single-label name is allowed, as in
    door-core's net.ts."""
    try:
        if not isinstance(origin, str):
            raise TypeError
        _check_authority(origin, "the registry origin")
        parsed = URL(origin)
    except (URLError, ValueError, TypeError):
        raise ValueError(f"the registry origin is not a plain URL: {origin!r}") from None
    if parsed.scheme == "https" and parsed.hostname:
        return parsed
    if parsed.scheme == "http" and is_loopback_host(parsed.hostname):
        return parsed
    raise ValueError("the registry origin must be https (plain http only on a loopback host)")
