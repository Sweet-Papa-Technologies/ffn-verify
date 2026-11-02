"""R3: status URIs and DID URLs must be https on a public host (no private or reserved
IP literal, no local or single-label name). Refused URLs are never requested, and
errors never echo what an untrusted host answered."""

from __future__ import annotations

import unittest

from fixtures import Web

from ffn_verify import DidResolver, StatusChecker
from ffn_verify._egress import RefusedURL, check_public_https, is_loopback_host, refused_host

REFUSED_HOSTS = [
    # IPv4: unspecified, private, CGNAT, loopback, link-local, multicast, reserved, broadcast, documentation
    "0.0.0.0", "0.1.2.3", "10.0.0.5", "100.64.0.1", "100.127.255.254", "127.0.0.1", "127.1.2.3", "169.254.169.254",
    "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.7",
    "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
    # IPv6: unspecified, loopback, IPv4-mapped private, NAT64 of private, 6to4 (any), ULA, link-local,
    # site-local, multicast, documentation, discard, Teredo, non-global-unicast space
    "[::]", "[::1]", "[::ffff:a00:5]", "[::ffff:7f00:1]", "[64:ff9b::a00:5]", "[2002:a00:5::1]",
    "[2002:808:808::1]", "[fc00::1]", "[fd12:3456::1]", "[fe80::1]", "[fec0::1]", "[ff02::1]", "[2001:db8::1]",
    "[100::1]", "[2001::1]", "[3fff::1]", "[4000::1]", "[::a00:5]",
    # names: local, and single-label (resolved through the local search domains)
    "localhost", "localhost.", "localhost..", "foo.localhost", "printer.local", "printer.local.",
    "metadata.google.internal", "LOCALHOST", "Printer.Local", "metadata", "printer", "intranet", "router.",
    "com", "xn--p1ai",
]
ALLOWED_HOSTS = ["registry.fofo.network", "8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "[2606:4700::1111]",
                 "[::ffff:808:808]", "[64:ff9b::808:808]", "local.example", "internal.example",
                 "localhost.example.com", "registry.fofo.network.", "a.b"]

REFUSED_URLS = [
    "http://registry.test/status/1",  # not https
    "HTTPS://registry.test/status/1",  # not the exact scheme the TS accepts either
    "https://10.0.0.5:8443/admin",
    "https://0x7f.1/x",  # 127.0.0.1 to the WHATWG parser
    "https://2130706433/x",  # 127.0.0.1
    "https://%31%32%37.0.0.1/x",
    "https://[::ffff:127.0.0.1]/x",
    "https://169.254.169.254/latest/meta-data/",
    "https://metadata.google.internal/computeMetadata/v1/",
    "https://evil.example\\@10.0.0.5/x",  # urllib and WHATWG read the host differently
    "https://user@registry.test/status/1",
    "https://registry.test /status/1",
    "https://bücher.example/status",  # non-ASCII authority (IDNA 2003 vs UTS 46)
    "https:///status",
]


class HostPolicy(unittest.TestCase):
    def test_refuses_private_local_and_reserved_hosts(self) -> None:
        for host in REFUSED_HOSTS:
            with self.subTest(host=host):
                self.assertTrue(refused_host(host.lower() if not host.startswith("[") else host))
                with self.assertRaises(RefusedURL):
                    check_public_https(f"https://{host}/x")

    def test_allows_public_hosts(self) -> None:
        for host in ALLOWED_HOSTS:
            with self.subTest(host=host):
                self.assertFalse(refused_host(host))
                check_public_https(f"https://{host}/status/1")

    def test_refuses_urls_that_are_not_plain_public_https(self) -> None:
        for url in REFUSED_URLS:
            with self.subTest(url=url), self.assertRaises(RefusedURL):
                check_public_https(url)

    def test_loopback_hosts(self) -> None:
        for host in ("127.0.0.1", "127.9.9.9", "[::1]", "[::ffff:7f00:1]", "localhost", "LOCALHOST", "localhost.",
                     "foo.localhost"):
            self.assertTrue(is_loopback_host(host), host)
        for host in ("10.0.0.1", "example.com", "[fe80::1]", "localhost.example", "[::2]"):
            self.assertFalse(is_loopback_host(host), host)


class NoRequest(unittest.TestCase):
    def test_a_did_on_a_refused_host_is_never_fetched(self) -> None:
        for did in ("did:web:10.0.0.9%3A9443:internal:svc", "did:web:127.0.0.1", "did:web:localhost%3A8080",
                    "did:web:metadata.google.internal", "did:web:printer.local", "did:web:%5B%3A%3A1%5D",
                    "did:web:0x7f.1", "did:web:metadata", "did:web:printer:agents:x", "did:web:intranet%3A8443"):
            with self.subTest(did=did):
                fetch = Web()
                with self.assertRaisesRegex(ValueError, f"could not resolve {did}"):
                    DidResolver(fetch=fetch).resolve(did)
                self.assertEqual(fetch.log, [])

    def test_a_status_uri_on_a_refused_host_is_never_fetched(self) -> None:
        for uri in ("https://10.0.0.5:8443/admin/reset?all=1", "https://[::1]/s", "http://registry.test/status/1",
                    "https://svc.internal/s", "https://evil.example\\@10.0.0.5/x", "https://metadata/computeMetadata",
                    "https://printer:631/s", "https://router./s"):
            with self.subTest(uri=uri):
                fetch = Web()
                checker = StatusChecker(resolver=DidResolver(fetch=fetch), fetch=fetch, now=lambda: 0)
                with self.assertRaises(ValueError):
                    checker.check({"status_list": {"idx": 0, "uri": uri}}, "did:web:issuer.example")
                self.assertEqual(fetch.log, [])

    def test_resolution_errors_do_not_echo_the_remote_answer(self) -> None:
        for status in (401, 404, 500, 302):
            with self.subTest(status=status):
                fetch = Web({"https://attacker.example/.well-known/did.json":
                             (status, "text/plain", b"internal admin token abc123")})
                with self.assertRaises(ValueError) as caught:
                    DidResolver(fetch=fetch).resolve("did:web:attacker.example")
                message = str(caught.exception)
                self.assertNotIn(str(status), message)
                self.assertNotIn("abc123", message)
                self.assertEqual(getattr(caught.exception, "missing"), 400 <= status < 500)
        fetch = Web({"https://attacker.example/.well-known/did.json": ConnectionError("10.0.0.5 said abc123")})
        with self.assertRaises(ValueError) as caught:
            DidResolver(fetch=fetch).resolve("did:web:attacker.example")
        self.assertNotIn("abc123", str(caught.exception))
        fetch = Web({"https://attacker.example/.well-known/did.json": (200, "text/plain", b"abc123 is not JSON")})
        with self.assertRaises(ValueError) as caught:
            DidResolver(fetch=fetch).resolve("did:web:attacker.example")
        self.assertNotIn("abc123", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
