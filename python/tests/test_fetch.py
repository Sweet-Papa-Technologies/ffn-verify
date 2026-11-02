"""R4: every read is bounded. Size caps per kind of response (enforced while reading,
custom fetches included), a total time limit per request, no redirects, and an https
registry origin (plain http only on loopback)."""

from __future__ import annotations

import http.server
import io
import socketserver
import threading
import time
import unittest

from fixtures import NOW, REGISTRY_ORIGIN, MiniWorld, Web

from ffn_verify import DidResolver, StatusChecker, doh_resolver, lookup_business, static_txt, urllib_fetch, \
    verify_business
from ffn_verify.fetch import (DID_DOCUMENT_MAX, DNS_ANSWER_MAX, REGISTRY_RESPONSE_MAX, STATUS_LIST_MAX, FetchError,
                              FetchTimeout, ResponseTooLarge, bounded_fetch)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._serve()
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client gave up, as it should

    def _serve(self) -> None:
        if self.path == "/slow-headers":
            self.wfile.write(b"HTTP/1.1 200 OK\r\n")
            for _ in range(20):
                self.wfile.write(b"x-slow: 1\r\n")
                self.wfile.flush()
                time.sleep(0.25)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("location", "/ok")
            self.end_headers()
            return
        if self.path == "/missing":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"secret error page")
            return
        self.send_response(200)
        self.send_header("content-type", "application/json")
        if self.path == "/declared-big":
            self.send_header("content-length", str(10 * 1024 * 1024))
        self.end_headers()
        if self.path == "/slow-body":
            for _ in range(20):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.25)
        elif self.path in ("/big", "/declared-big"):
            chunk = b" " * 65536
            for _ in range(160):  # 10 MiB
                self.wfile.write(chunk)
        else:
            self.wfile.write(b'{"ok": true}')


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class DefaultFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _Server(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_a_trickled_body_stops_at_the_total_deadline(self) -> None:
        t = time.monotonic()
        with self.assertRaises(FetchTimeout):
            urllib_fetch(f"{self.base}/slow-body", {}, timeout=1)
        self.assertLess(time.monotonic() - t, 2.5)

    def test_trickled_headers_stop_at_the_total_deadline(self) -> None:
        t = time.monotonic()
        with self.assertRaises(FetchTimeout):
            urllib_fetch(f"{self.base}/slow-headers", {}, timeout=1)
        self.assertLess(time.monotonic() - t, 2.5)

    def test_reading_stops_at_the_cap(self) -> None:
        with self.assertRaises(ResponseTooLarge):
            urllib_fetch(f"{self.base}/big", {}, max_bytes=DID_DOCUMENT_MAX)
        with self.assertRaises(ResponseTooLarge):  # refused on the declared length, before reading
            urllib_fetch(f"{self.base}/declared-big", {}, max_bytes=STATUS_LIST_MAX)
        # The default cap is the largest one (status lists, 2 MiB), so a wrapper of
        # urllib_fetch can't be made to read 10 MiB either.
        with self.assertRaises(ResponseTooLarge):
            urllib_fetch(f"{self.base}/big", {})
        self.assertEqual(urllib_fetch(f"{self.base}/ok", {})[2], b'{"ok": true}')

    def test_redirects_are_not_followed(self) -> None:
        status, _, body = urllib_fetch(f"{self.base}/redirect", {})
        self.assertEqual(status, 302)
        self.assertEqual(body, b"")

    def test_error_bodies_are_not_read(self) -> None:
        self.assertEqual(urllib_fetch(f"{self.base}/missing", {}), (404, "", b""))

    def test_plain_http_only_to_loopback(self) -> None:
        self.assertEqual(urllib_fetch(f"{self.base}/ok", {})[0], 200)
        for url in ("http://example.com/", "http://10.0.0.5/", "file:///etc/passwd", "ftp://example.com/"):
            with self.subTest(url=url), self.assertRaises(FetchError):
                urllib_fetch(url, {})

    def test_a_did_document_over_64_kib_fails_through_a_wrapper_too(self) -> None:
        big = f"{self.base}/big"
        resolver = DidResolver(fetch=lambda url, headers: urllib_fetch(big, headers))
        with self.assertRaisesRegex(ValueError, "too large"):
            resolver.resolve("did:web:victim.example")


def _stream(size: int, log: list[int]) -> io.RawIOBase:
    class Stream(io.RawIOBase):
        def __init__(self) -> None:
            self.left = size

        def readable(self) -> bool:
            return True

        def readinto(self, b: bytearray) -> int:  # type: ignore[override]
            n = min(len(b), self.left, 65536)
            b[:n] = b" " * n
            self.left -= n
            log.append(n)
            return n

    return Stream()


class CustomFetch(unittest.TestCase):
    def test_a_streamed_body_is_read_only_up_to_the_cap(self) -> None:
        log: list[int] = []
        fetch = Web({"https://x.example/a": lambda: (200, "application/json", _stream(64 * 1024 * 1024, log))})
        with self.assertRaises(ResponseTooLarge):
            bounded_fetch(fetch, "https://x.example/a", {}, max_bytes=DID_DOCUMENT_MAX)
        self.assertLessEqual(sum(log), DID_DOCUMENT_MAX + 65536)

    def test_an_iterable_body_is_read_only_up_to_the_cap(self) -> None:
        pulled = []

        def chunks():
            for _ in range(1000):
                pulled.append(1)
                yield b" " * 65536

        fetch = Web({"https://x.example/a": lambda: (200, "text/plain", chunks())})
        with self.assertRaises(ResponseTooLarge):
            bounded_fetch(fetch, "https://x.example/a", {}, max_bytes=REGISTRY_RESPONSE_MAX)
        self.assertLessEqual(len(pulled), REGISTRY_RESPONSE_MAX // 65536 + 1)

    def test_a_slow_stream_stops_at_the_deadline(self) -> None:
        def slow():
            for _ in range(100):
                time.sleep(0.1)
                yield b" "

        fetch = Web({"https://x.example/a": lambda: (200, "text/plain", slow())})
        t = time.monotonic()
        with self.assertRaises(FetchTimeout):
            bounded_fetch(fetch, "https://x.example/a", {}, max_bytes=DNS_ANSWER_MAX, timeout=0.5)
        self.assertLess(time.monotonic() - t, 1.5)

    def test_a_late_answer_is_a_failed_fetch(self) -> None:
        def late():
            time.sleep(0.3)
            return 200, "text/plain", b"ok"

        with self.assertRaises(FetchTimeout):
            bounded_fetch(Web({"https://x.example/a": late}), "https://x.example/a", {}, max_bytes=10, timeout=0.1)

    def test_bytes_over_the_cap_fail(self) -> None:
        fetch = Web({"https://x.example/a": (200, "text/plain", b" " * 11)})
        with self.assertRaises(ResponseTooLarge):
            bounded_fetch(fetch, "https://x.example/a", {}, max_bytes=10)
        fetch.routes["https://x.example/a"] = (200, "text/plain", b" " * 10)
        self.assertEqual(bounded_fetch(fetch, "https://x.example/a", {}, max_bytes=10)[2], b" " * 10)

    def test_a_non_2xx_body_is_never_read(self) -> None:
        log: list[int] = []
        fetch = Web({"https://x.example/a": lambda: (500, "text/plain", _stream(1000, log))})
        self.assertEqual(bounded_fetch(fetch, "https://x.example/a", {}, max_bytes=10), (500, "text/plain", b""))
        self.assertEqual(log, [])


class Caps(unittest.TestCase):
    """Each kind of response has its own cap, and over it the check fails closed."""

    def test_did_json_over_64_kib_fails_the_binding(self) -> None:
        w = MiniWorld()
        doc_url = "https://biz.example/.well-known/did.json"
        body = w.web.routes[doc_url][2]
        padded = body[:-1] + b', "pad": "' + b"x" * DID_DOCUMENT_MAX + b'"}'
        w.web.routes[doc_url] = (200, "application/json", padded)
        r = verify_business("biz.example", registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW)
        self.assertFalse(r["verified"])
        self.assertEqual(r["failure"]["code"], "binding_unreachable")

    def test_a_registry_answer_over_1_mib_is_registry_unavailable(self) -> None:
        w = MiniWorld()
        url = f"{REGISTRY_ORIGIN}/v1/lookup?domain=biz.example"
        w.web.routes[url] = (200, "application/ffn-business-record+jwt", b"x" * (REGISTRY_RESPONSE_MAX + 1))
        r = verify_business("biz.example", registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW)
        self.assertEqual(r["failure"]["code"], "registry_unavailable")
        self.assertIn("too large", r["failure"]["message"])

    def test_a_status_list_over_2_mib_is_unknown(self) -> None:
        w = MiniWorld()
        w.web.routes["https://registry.test/status/1"] = (200, "application/statuslist+jwt",
                                                          b"x" * (STATUS_LIST_MAX + 1))
        checker = StatusChecker(resolver=DidResolver(fetch=w.web), fetch=w.web, now=lambda: NOW)
        ref = {"status_list": {"idx": 0, "uri": "https://registry.test/status/1"}}
        self.assertEqual(checker.check(ref, "did:web:registry.test"), {"status": "unknown"})

    def test_a_doh_answer_over_64_kib_fails_the_lookup(self) -> None:
        url = "https://cloudflare-dns.com/dns-query?name=_ffn.biz.example&type=TXT"
        fetch = Web({url: (200, "application/dns-json", b'{"Status":0,"Answer":[]' + b" " * DNS_ANSWER_MAX + b"}")})
        with self.assertRaises(ResponseTooLarge):
            doh_resolver(fetch=fetch).txt("_ffn.biz.example")
        fetch.routes[url] = (200, "application/dns-json", b'{"Status":0,"Answer":[]}')
        self.assertEqual(doh_resolver(fetch=fetch).txt("_ffn.biz.example"), [])

    def test_the_timeout_is_configurable(self) -> None:
        w = MiniWorld()
        url = f"{REGISTRY_ORIGIN}/v1/lookup?domain=biz.example"
        answer = w.web.routes[url]

        def slow():
            time.sleep(0.3)
            return answer

        w.web.routes[url] = slow
        r = verify_business("biz.example", registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW,
                            timeout=0.1)
        self.assertEqual(r["failure"]["code"], "registry_unavailable")
        r = verify_business("biz.example", registry=w.registry, fetch=w.web, dns=static_txt(w.dns), now=NOW,
                            timeout=5)
        self.assertTrue(r["verified"], r["summary"])


class RegistryOrigin(unittest.TestCase):
    def test_must_be_https_or_loopback_http(self) -> None:
        # The caller chooses the origin, so a single-label https host is allowed, as in TS (net.ts).
        for origin in ("http://registry.example", "ftp://registry.example", "registry.example", "http://10.0.0.1",
                       "https://user@registry.example", "https://registry.example\\@evil.example"):
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(ValueError, "registry origin"):
                    verify_business("biz.example", registry={"origin": origin}, fetch=Web(), dns=static_txt({}))
                with self.assertRaisesRegex(ValueError, "registry origin"):
                    lookup_business(registry={"origin": origin}, domain="biz.example", fetch=Web())
        for origin in ("http://127.0.0.1:8787", "http://[::1]:8787", "http://api.localhost:8787",
                       "https://127.0.0.1:8443", "https://registry.test", "https://registry", "https://registry.",
                       "http://localhost:8787", "https://localhost"):
            with self.subTest(origin=origin):
                fetch = Web()
                r = verify_business("biz.example", registry={"origin": origin}, fetch=fetch, dns=static_txt({}))
                self.assertEqual(r["failure"]["code"], "not_in_registry")
                self.assertTrue(fetch.log[0].startswith(origin))


if __name__ == "__main__":
    unittest.main()
