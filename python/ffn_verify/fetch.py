"""The fetch the verifier is built on, and the stdlib default.

A fetch is any callable ``fetch(url, headers) -> (status, content_type, body)``:
``headers`` carries the Accept header the TS sends (DNS-over-HTTPS JSON needs it),
an HTTP error status is returned rather than raised, and only a network failure
raises. Tests replace it with a table lookup.

Every read the verifier makes is bounded (see ``bounded_fetch``):

* a size cap per kind of response (``DID_DOCUMENT_MAX`` and so on), enforced while
  the body is read: over the cap, reading stops and the fetch counts as failed;
* a total time limit per request (connect, headers and body), 10 s by default;
* redirects are never followed: a 3xx is a failed fetch.

``body`` may be ``bytes`` (or ``str``), or a stream: a file-like object with
``read``/``read1``, or an iterable of ``bytes`` chunks. A custom fetch that returns a
stream gets the size cap and the deadline applied while the verifier reads it; one
that returns ``bytes`` has already read the whole body, so only the result is checked.
A custom fetch should apply its own connect and read timeouts: the verifier can't
interrupt a call that blocks before it returns.
"""

from __future__ import annotations

import http.client
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping

from ._egress import is_loopback_host
from ._version import __version__
from .url import URL

Fetch = Callable[[str, Mapping[str, str]], "tuple[int, str, Any]"]

KIB = 1024
MIB = 1024 * KIB
DID_DOCUMENT_MAX = 64 * KIB
DNS_ANSWER_MAX = 64 * KIB
REGISTRY_RESPONSE_MAX = 1 * MIB
STATUS_LIST_MAX = 2 * MIB
DEFAULT_TIMEOUT = 10.0
_CHUNK = 64 * KIB


class FetchError(OSError):
    """A fetch the verifier gave up on."""


class FetchTimeout(FetchError, TimeoutError):
    """The request took longer than its total time limit."""


class ResponseTooLarge(FetchError):
    """The body is larger than the cap for what was asked for. Reading stopped there."""


class _Watchdog:
    """Shuts a request's sockets down when its time is up, so a host that trickles its
    headers or body (a byte every few seconds never trips a socket timeout) can't hold a
    verification past the deadline. Each watched socket is a dup the watchdog owns, so
    it never acts on a descriptor the request has closed and something else reused."""

    def __init__(self, seconds: float):
        self._lock = threading.Lock()
        self._socks: list[socket.socket] = []
        self.fired = False
        self._done = False
        self._timer = threading.Timer(max(seconds, 0.0), self._fire)
        self._timer.daemon = True

    def __enter__(self) -> _Watchdog:
        self._timer.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._timer.cancel()
        with self._lock:
            self._done = True
            socks, self._socks = self._socks, []
        for s in socks:
            s.close()

    def _fire(self) -> None:
        with self._lock:
            if self._done:
                return
            self.fired = True
            for s in self._socks:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def watch(self, sock: socket.socket) -> None:
        try:
            dup = sock.dup()
        except OSError:
            return
        with self._lock:
            if not self._done:
                self._socks.append(dup)
                if self.fired:
                    try:
                        dup.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                return
        dup.close()


def _watched(http_class: type, watchdog: _Watchdog) -> type:
    """``http_class`` with every socket it opens handed to the watchdog."""

    class Watched(http_class):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)

            def create_connection(*a: Any, **kw: Any) -> socket.socket:
                sock = socket.create_connection(*a, **kw)
                watchdog.watch(sock)
                return sock

            self._create_connection = create_connection

    return Watched


class _HTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, watchdog: _Watchdog):
        super().__init__()
        self._watchdog = watchdog

    def do_open(self, http_class, req, **kwargs):  # type: ignore[no-untyped-def, override]
        return super().do_open(_watched(http_class, self._watchdog), req, **kwargs)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, watchdog: _Watchdog):
        super().__init__()
        self._watchdog = watchdog

    def do_open(self, http_class, req, **kwargs):  # type: ignore[no-untyped-def, override]
        return super().do_open(_watched(http_class, self._watchdog), req, **kwargs)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    # A did:web is the document at exactly its URL, and nothing else here should
    # follow a redirect either: a 3xx comes back as a status, like fetch's redirect: 'manual'.
    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


def _check_scheme(url: str) -> None:
    # HTTPS, as fetch() in Node, and never a local file. Plain http only to a loopback
    # host, for a registry under local test.
    if url.lower().startswith("https://"):
        return
    if url.lower().startswith("http://"):
        try:
            if is_loopback_host(URL(url).hostname):
                return
        except ValueError:
            pass
        raise FetchError("plain http is allowed only to a loopback host")
    raise FetchError("unsupported URL scheme")


def urllib_fetch(url: str, headers: Mapping[str, str] | None = None, *, timeout: float = DEFAULT_TIMEOUT,
                 max_bytes: int | None = STATUS_LIST_MAX) -> tuple[int, str, bytes]:
    """The default fetch: urllib (honoring proxy environment variables), no redirects,
    ``timeout`` seconds in total for connect, headers and body, at most ``max_bytes``
    of body (None: no cap). Over either limit it raises FetchTimeout or ResponseTooLarge.
    The body of an HTTP error response is not read (b"" is returned)."""
    _check_scheme(url)
    request = urllib.request.Request(url, headers={"user-agent": f"ffn-verify/{__version__}", **(headers or {})})
    deadline = time.monotonic() + timeout
    with _Watchdog(timeout) as watchdog:
        opener = urllib.request.build_opener(_NoRedirects, _HTTPHandler(watchdog), _HTTPSHandler(watchdog))
        try:
            res = opener.open(request, timeout=max(deadline - time.monotonic(), 0.001))
        except urllib.error.HTTPError as err:
            content_type = err.headers.get("content-type", "") if err.headers else ""
            err.close()
            if watchdog.fired:
                raise FetchTimeout("timed out") from None
            return err.code, content_type, b""
        except Exception as err:
            if watchdog.fired or isinstance(err, TimeoutError) or isinstance(
                    getattr(err, "reason", None), TimeoutError):
                raise FetchTimeout("timed out") from None
            raise
        try:
            length = res.headers.get("content-length")
            if max_bytes is not None and length and length.strip().isdigit() and int(length) > max_bytes:
                raise ResponseTooLarge("response too large")
            body = _read_stream(res, max_bytes, deadline, watchdog)
            return res.status, res.headers.get("content-type", ""), body
        except (FetchError, http.client.HTTPException, OSError, ValueError) as err:
            if watchdog.fired and not isinstance(err, ResponseTooLarge):
                raise FetchTimeout("timed out") from None
            raise
        finally:
            res.close()


def _read_stream(stream: Any, max_bytes: int | None, deadline: float, watchdog: _Watchdog | None = None) -> bytes:
    read = getattr(stream, "read1", None) or stream.read
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline or (watchdog is not None and watchdog.fired):
            raise FetchTimeout("timed out")
        chunk = read(_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise ResponseTooLarge("response too large")
        chunks.append(bytes(chunk))
    if watchdog is not None and watchdog.fired:
        raise FetchTimeout("timed out")  # a shutdown reads as an early end
    return b"".join(chunks)


def _read_body(body: Any, max_bytes: int, deadline: float) -> bytes:
    """A custom fetch's body: bytes or str as is (capped), a stream read up to the cap."""
    if isinstance(body, (bytes, bytearray, memoryview)):
        data = bytes(body)
    elif isinstance(body, str):
        data = body.encode("utf-8", "surrogatepass")
    elif hasattr(body, "read"):
        return _read_stream(body, max_bytes, deadline)
    elif hasattr(body, "__iter__"):
        chunks: list[bytes] = []
        total = 0
        for chunk in body:
            if time.monotonic() > deadline:
                raise FetchTimeout("timed out")
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "surrogatepass")
            total += len(chunk)
            if total > max_bytes:
                raise ResponseTooLarge("response too large")
            chunks.append(bytes(chunk))
        return b"".join(chunks)
    else:
        raise TypeError("a fetch must return bytes, str or a stream as the body")
    if len(data) > max_bytes:
        raise ResponseTooLarge("response too large")
    return data


def _close(body: Any) -> None:
    close = getattr(body, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def bounded_fetch(fetch: Fetch | None, url: str, headers: Mapping[str, str], *, max_bytes: int,
                  timeout: float = DEFAULT_TIMEOUT) -> tuple[int, str, bytes]:
    """``fetch(url, headers)`` held to ``max_bytes`` of body and ``timeout`` seconds in all.

    The default fetch enforces both while it reads. A custom fetch's stream is read up
    to the cap and the deadline; past the deadline the result is discarded. Raises
    FetchTimeout or ResponseTooLarge (failed fetches); the body of a non-2xx answer is
    never read and comes back as b""."""
    if fetch is None or fetch is urllib_fetch:
        return urllib_fetch(url, headers, timeout=timeout, max_bytes=max_bytes)
    deadline = time.monotonic() + timeout
    status, content_type, body = fetch(url, headers)
    try:
        if not ok(status):
            return status, content_type, b""
        data = _read_body(body, max_bytes, deadline)
    finally:
        _close(body)
    if time.monotonic() > deadline:
        raise FetchTimeout("timed out")
    return status, content_type, data


def ok(status: int) -> bool:
    return 200 <= status <= 299


def text_of(body: bytes | str) -> str:
    """Response.text(): UTF-8 with replacement, leading BOM dropped."""
    text = body if isinstance(body, str) else body.decode("utf-8", "replace")
    return text[1:] if text.startswith("\ufeff") else text
