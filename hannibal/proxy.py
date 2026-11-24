"""Scope-enforcing recording proxy — the runtime network backstop.

The scope guard (scope.py) checks a command *before* it runs, reasoning about
the targets in its argument vector. That is a static check of declared intent,
and by construction it cannot see where traffic actually goes once a tool is
live: an HTTP client following a 302 redirect to another host, a hostname that
resolves to a different address at runtime, an out-of-band callback. None of
those appear in the argument vector, so the static guard is blind to them.

This proxy is the second enforcement site, on the network path. Every HTTP
request and every HTTPS CONNECT a tool makes passes through it, and the
destination host is checked against the *same* ScopeGuard the static guard uses
— one scope definition, enforced in two places. A destination outside scope is
refused at the socket, logged to the audit trail, and recorded as a blocked
attempt. Nothing leaves the authorized scope even if a tool is steered off it
at runtime.

It also records request/response transcripts for in-scope HTTP traffic, so a
later validation pass can corroborate a detection against the real response body
the tool actually received (see validator.enrich_evidence).

Phase 1 is stdlib-only and does NOT intercept TLS. For an HTTPS CONNECT it sees
and enforces the destination host — enough for the scope backstop — but tunnels
the encrypted bytes untouched, so there is no body capture on HTTPS. Plain-HTTP
traffic is captured in full. TLS interception (body capture on HTTPS) is a
deliberate later phase: it needs a local CA and a dependency, and the honest
floor here is the scope backstop for every protocol plus evidence capture for
HTTP.
"""
from __future__ import annotations

import http.client
import io
import select
import socket
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

# A scope check: returns None if the host is in scope, else a reason string.
# ScopeGuard.why_out_of_scope has exactly this shape, so the proxy reuses it
# instead of reimplementing scope logic — one source of truth, two call sites.
ScopeCheck = Callable[[str], Optional[str]]
# Optional injection scan: untrusted body -> True if it looks hostile.
BodyScan = Callable[[str], bool]
# Optional block hook: (host, reason, kind) -> None, e.g. to write an audit line.
BlockHook = Callable[[str, str, str], None]

# cap a captured body so a huge response can't blow up memory; 20 KiB is plenty
# to corroborate an env-file / git-config / dump detection
_MAX_BODY = 20_000


@dataclass
class Exchange:
    """One in-scope HTTP request/response the proxy forwarded and recorded."""
    url: str
    status: int
    body: str
    suspicious: bool = False


@dataclass
class Blocked:
    """One request the proxy refused because its destination was out of scope."""
    host: str
    reason: str
    kind: str   # "http" | "connect"


class Transcript:
    """Thread-safe record of what the proxy forwarded and what it blocked."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.exchanges: List[Exchange] = []
        self.blocked: List[Blocked] = []
        self._by_url: Dict[str, Exchange] = {}

    def record_exchange(self, ex: Exchange) -> None:
        with self._lock:
            self.exchanges.append(ex)
            self._by_url[ex.url.rstrip("/")] = ex

    def record_block(self, b: Blocked) -> None:
        with self._lock:
            self.blocked.append(b)

    def body_for(self, url: str) -> Optional[Exchange]:
        """The captured exchange for a URL, matching a trailing query/path
        loosely so a detection's `matched-at` still lines up with the request."""
        with self._lock:
            u = (url or "").rstrip("/")
            if not u:
                return None
            if u in self._by_url:
                return self._by_url[u]
            for key, ex in self._by_url.items():
                if u.startswith(key) or key.startswith(u):
                    return ex
            return None


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # the server instance carries the shared ScopeProxy context
    @property
    def _ctx(self) -> "ScopeProxy":
        return self.server._ctx          # type: ignore[attr-defined]

    def log_message(self, *args) -> None:   # silence stderr request logging
        return

    # -- shared deny path ---------------------------------------------------
    def _deny(self, host: str, reason: str, kind: str) -> None:
        self._ctx.transcript.record_block(Blocked(host, reason, kind))
        self._ctx._fire_block(host, reason, kind)
        body = (f"blocked by Hannibal scope guard: {reason}").encode("utf-8", "replace")
        try:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    # -- HTTPS: enforce the host; tunnel (Phase 1) or intercept (Phase 2) ----
    def do_CONNECT(self) -> None:
        host = self.path.rsplit(":", 1)[0].strip("[]")
        reason = self._ctx.scope_check(host)
        if reason is not None:
            self._deny(host, reason, "connect")
            return
        try:
            port = int(self.path.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            port = 443

        # Phase 2: terminate the client's TLS, read the decrypted HTTP, forward
        # over our own TLS to the real upstream — so HTTPS bodies are captured.
        # Only reached for an in-scope host, and only when a CA is configured.
        if self._ctx.ca is not None:
            self._intercept(host, port)
            return

        # Phase 1: enforce the destination, then tunnel the opaque bytes.
        try:
            upstream = socket.create_connection((host, port), timeout=self._ctx.timeout)
        except OSError as e:
            self._deny(host, f"upstream connect failed: {e}", "connect")
            return
        try:
            self.send_response(200, "Connection established")
            self.end_headers()
        except OSError:
            upstream.close()
            return
        self._tunnel(self.connection, upstream)
        self.close_connection = True

    def _intercept(self, host: str, port: int) -> None:
        """Man-in-the-middle an in-scope HTTPS CONNECT so the body is visible."""
        try:
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
        except OSError:
            self.close_connection = True
            return
        try:
            server_ctx = self._ctx.ca.context_for(host)
            tls_client = server_ctx.wrap_socket(self.connection, server_side=True)
        except (OSError, ssl.SSLError):
            # a client that refuses our leaf (e.g. strict pinning) just fails
            # closed — nothing left scope, and nothing was captured
            self.close_connection = True
            return
        try:
            self._ctx._serve_decrypted(tls_client, host, port)
        finally:
            try:
                tls_client.close()
            except OSError:
                pass
            # the raw socket is now spent; hand the outer handler inert buffers
            # so its finish() can't write to a closed TLS socket
            self.rfile = io.BytesIO()
            self.wfile = io.BytesIO()
            self.close_connection = True

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        """Pump bytes both ways until either side closes. The payload is opaque
        (TLS) — we enforced the destination before opening it, and we do not
        read it."""
        socks = [client, upstream]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, self._ctx.timeout)
                if x or not r:
                    break
                for s in r:
                    other = upstream if s is client else client
                    try:
                        data = s.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        other.sendall(data)
                    except OSError:
                        return
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    # -- HTTP: enforce the host, forward, record the exchange ---------------
    def _proxy_http(self) -> None:
        parts = urlsplit(self.path)
        host = parts.hostname
        if not host:
            self._deny(self.path or "?", "proxied request had no host", "http")
            return
        reason = self._ctx.scope_check(host)
        if reason is not None:
            self._deny(host, reason, "http")
            return
        port = parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        length = int(self.headers.get("Content-Length", 0) or 0)
        req_body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("proxy-connection", "connection")}

        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=self._ctx.timeout)
            conn.request(self.command, path, body=req_body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except OSError as e:
            self._deny(host, f"upstream error: {e}", "http")
            if conn is not None:
                conn.close()
            return

        text = raw.decode("utf-8", "replace")
        shown = f"" if port == 80 else f":{port}"
        url = f"http://{host}{shown}{path}"
        suspicious = bool(self._ctx.scan(text)) if self._ctx.scan else False
        self._ctx.transcript.record_exchange(
            Exchange(url, resp.status, text[:_MAX_BODY], suspicious))

        try:
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in ("transfer-encoding", "connection", "content-length"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            pass
        finally:
            conn.close()
        self.close_connection = True

    # every proxied verb routes through the one handler above
    do_GET = do_POST = do_HEAD = do_PUT = _proxy_http
    do_DELETE = do_OPTIONS = do_PATCH = _proxy_http


class _DecryptedServer:
    """A minimal stand-in for an HTTPServer, carrying the context an
    _InterceptHandler needs for one intercepted CONNECT (its proxy, and the
    authoritative host/port the client connected to)."""

    def __init__(self, proxy: "ScopeProxy", host: str, port: int):
        self.proxy = proxy
        self.host = host
        self.port = port


class _InterceptHandler(BaseHTTPRequestHandler):
    """Handles the plaintext HTTP requests inside an intercepted TLS tunnel.

    Requests here are origin-form (`GET /path`), so the URL is rebuilt from the
    CONNECT host (authoritative — not the client's Host header) and forwarded to
    the real upstream over TLS. Supports keep-alive, so a scanner reusing the
    connection for many requests is captured in full."""

    protocol_version = "HTTP/1.1"

    @property
    def _p(self) -> "ScopeProxy":
        return self.server.proxy          # type: ignore[attr-defined]

    def log_message(self, *args) -> None:
        return

    def _deny(self, reason: str) -> None:
        host = self.server.host           # type: ignore[attr-defined]
        self._p.transcript.record_block(Blocked(host, reason, "https"))
        self._p._fire_block(host, reason, "https")
        body = (f"blocked by Hannibal scope guard: {reason}").encode("utf-8", "replace")
        try:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def _handle(self) -> None:
        host = self.server.host           # type: ignore[attr-defined]
        port = self.server.port           # type: ignore[attr-defined]
        # defence in depth: the CONNECT host was scope-checked, but re-check
        reason = self._p.scope_check(host)
        if reason is not None:
            self._deny(reason)
            return
        path = self.path or "/"
        length = int(self.headers.get("Content-Length", 0) or 0)
        req_body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("proxy-connection", "connection")}

        conn = None
        try:
            up_ctx = ssl._create_unverified_context()   # labs use self-signed
            conn = http.client.HTTPSConnection(
                host, port, timeout=self._p.timeout, context=up_ctx)
            conn.request(self.command, path, body=req_body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except OSError as e:
            self._deny(f"upstream error: {e}")
            if conn is not None:
                conn.close()
            return

        text = raw.decode("utf-8", "replace")
        shown = "" if port == 443 else f":{port}"
        url = f"https://{host}{shown}{path}"
        suspicious = bool(self._p.scan(text)) if self._p.scan else False
        self._p.transcript.record_exchange(
            Exchange(url, resp.status, text[:_MAX_BODY], suspicious))

        try:
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in ("transfer-encoding", "connection", "content-length"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            pass
        finally:
            conn.close()

    do_GET = do_POST = do_HEAD = do_PUT = _handle
    do_DELETE = do_OPTIONS = do_PATCH = _handle


class ScopeProxy:
    """A running forward proxy that enforces scope on every connection.

    Reuse the orchestrator's existing guard directly::

        proxy = ScopeProxy(scope_guard.why_out_of_scope,
                           scan=lambda b: injection.scan(b).suspicious,
                           on_block=audit_hook).start()
        env["HTTP_PROXY"] = env["HTTPS_PROXY"] = proxy.address
        ...
        proxy.stop()
    """

    def __init__(self, scope_check: ScopeCheck, *,
                 scan: Optional[BodyScan] = None,
                 on_block: Optional[BlockHook] = None,
                 ca: Optional[Any] = None,
                 host: str = "127.0.0.1", port: int = 0,
                 timeout: float = 30.0):
        self.scope_check = scope_check
        self.scan = scan
        self._on_block = on_block
        # a CertAuthority (tls_intercept.CertAuthority) enables Phase-2 HTTPS
        # interception; None keeps Phase-1 tunnelling. Duck-typed so this module
        # never imports the optional `cryptography`-backed code.
        self.ca = ca
        self.timeout = timeout
        self.transcript = Transcript()
        self._server = ThreadingHTTPServer((host, port), _ProxyHandler)
        self._server._ctx = self            # type: ignore[attr-defined]
        self._server.daemon_threads = True
        self._thread: Optional[threading.Thread] = None

    def _fire_block(self, host: str, reason: str, kind: str) -> None:
        if self._on_block is None:
            return
        try:
            self._on_block(host, reason, kind)
        except Exception:
            pass   # a failing audit hook must never crash a worker

    def _serve_decrypted(self, tls_sock: socket.socket, host: str,
                         port: int) -> None:
        """Drive the decrypted HTTP conversation inside an intercepted CONNECT:
        read each request off the client's TLS socket, forward it to the real
        upstream over our own TLS, record the exchange, relay the response back.
        Runs in the worker thread that owns this connection."""
        shim = _DecryptedServer(self, host, port)
        try:
            _InterceptHandler(tls_sock, (host, port), shim)
        except (OSError, ssl.SSLError):
            pass

    @property
    def address(self) -> str:
        h, p = self._server.server_address[:2]
        return f"http://{h}:{p}"

    def start(self) -> "ScopeProxy":
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="hannibal-proxy", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._server.shutdown()
        finally:
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "ScopeProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def stats(self) -> Dict[str, int]:
        return {"forwarded": len(self.transcript.exchanges),
                "blocked": len(self.transcript.blocked)}
