"""normalize_domain against what door-core's normalizeDomain returns under Node 22.

The TS gets IDNA from the WHATWG URL parser; the Python approximates it with the
standard library (see ffn_verify/url.py). These expectations were recorded from
Node, so a drift on either side shows up here, not as a lookup that silently
asks the registry for a different name."""

from __future__ import annotations

import unittest

import fixtures  # noqa: F401  (puts the package next to these tests first on the path)

from ffn_verify import IdentifierError, normalize_domain

FROM_NODE = {
    "acme-hvac.example": "acme-hvac.example",
    " ACME-Heating.example. ": "acme-heating.example",
    "аcme-hvac.example": "xn--cme-hvac-06g.example",  # Cyrillic а
    "straße.de": "xn--strae-oqa.de",  # ß kept (non-transitional)
    "ΣΑΣ.gr": "xn--mxa9ab.gr",  # final sigma maps to σ
    "Ｅｘａｍｐｌｅ．com": "example.com",
    "x。y.com": "x.y.com",
    "a­b.com": "ab.com",
    "İstanbul.tr": "xn--istanbul-o0e.tr",
    "café.fr": "xn--caf-dma.fr",
    "\U0001f4a9.la": "xn--ls8h.la",
    "XN--CME-HVAC-8OF.example": "xn--cme-hvac-8of.example",
    "acme%2Dhvac.example": "acme-hvac.example",
    "a_b.com": "a_b.com",
    "aא.com": "xn--a-0hc.com",
    "می‌خواهم.com": "xn--mgbn2ecje63gr19l.com",  # Persian ZWNJ
    "क्‌ष.com": "xn--11b2ezcs70k.com",  # ZWNJ after a virama
}

REFUSED_BY_NODE = [
    "acme-hvac.example:443", "https://acme-hvac.example", "", "1.2.3.4", "127.1", "0x7f.1", "example.123",
    "xn--abc.example", "a‍b.com", "́a.com", "אa.com", "a⒈.com", "a<b.com", "acme%zz.example",
    "a\\b.com", "ab�.com", "metadata.google.internal", "printer.local", "router.home.arpa", "localhost",
]


class NormalizeDomain(unittest.TestCase):
    def test_matches_node(self) -> None:
        for raw, want in FROM_NODE.items():
            with self.subTest(raw=ascii(raw)):
                self.assertEqual(normalize_domain(raw), want)

    def test_refuses_what_node_refuses(self) -> None:
        for raw in REFUSED_BY_NODE:
            with self.subTest(raw=ascii(raw)):
                with self.assertRaises(IdentifierError):
                    normalize_domain(raw)


if __name__ == "__main__":
    unittest.main()
