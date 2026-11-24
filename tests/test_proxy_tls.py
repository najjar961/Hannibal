"""Tests for Phase-2 HTTPS interception (hannibal/tls_intercept.py + proxy.py).

Phase 1 enforces scope on an HTTPS CONNECT but tunnels the encrypted bytes, so
it never sees the body. Phase 2 terminates the client's TLS with a minted leaf,
forwards over its own TLS to the real upstream, and records the decrypted body —
so the validator can corroborate an HTTPS detection against the real response.

These tests stand up a genuine self-signed HTTPS origin and drive a real TLS
client through the proxy, asserting the body is captured and that scope is still
enforced at CONNECT. They skip cleanly if `cryptography` isn't installed, since
Phase 2 is an optional dependency.
"""
from __future__ import annotations

import http.client
import os
import socket
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from hannibal.scope import ScopeGuard
from hannibal.proxy import ScopeProxy
from hannibal import tls_intercept

OUT_OF_SCOPE = "10.99.99.99"
SECRET = b"DB_PASSWORD=hunter2\nAPI_TOKEN=s3cr3t\n"


def _self_signed(tmpdir):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cpath = os.path.join(tmpdir, "origin.crt")
    kpath = os.path.join(tmpdir, "origin.key")
    with open(cpath, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.TraditionalOpenSSL,
                 serialization.NoEncryption()))
    return cpath, kpath


class _Origin(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(SECRET)))
        self.end_headers()
        self.wfile.write(SECRET)


def _raw_connect(proxy_url, hostport):
    pu = urlsplit(proxy_url)
    s = socket.create_connection((pu.hostname, pu.port), timeout=10)
    try:
        s.sendall(f"CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n\r\n".encode())
        return s.recv(256).decode("latin1")
    finally:
        s.close()


@unittest.skipUnless(tls_intercept.AVAILABLE,
                     "cryptography not installed (Phase 2 is optional)")
class TlsInterceptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hannibal-test-")
        # a real self-signed HTTPS origin on 127.0.0.1
        cpath, kpath = _self_signed(self.tmp)
        self.origin = ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        octx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        octx.load_cert_chain(cpath, kpath)
        self.origin.socket = octx.wrap_socket(self.origin.socket, server_side=True)
        self.origin.daemon_threads = True
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.oport = self.origin.server_address[1]

        self.blocks = []
        self.ca = tls_intercept.make_ca(self.tmp)
        self.proxy = ScopeProxy(
            ScopeGuard(["127.0.0.1"]).why_out_of_scope,
            scan=lambda body: "DB_PASSWORD" in body,
            on_block=lambda h, r, k: self.blocks.append((h, k)),
            ca=self.ca,
        ).start()

    def tearDown(self):
        self.proxy.stop()
        self.origin.shutdown()
        self.origin.server_close()

    def _https_through_proxy(self, target_host, target_port, path="/"):
        pu = urlsplit(self.proxy.address)
        cctx = ssl._create_unverified_context()   # client trusts the minted leaf
        conn = http.client.HTTPSConnection(pu.hostname, pu.port, context=cctx,
                                           timeout=10)
        conn.set_tunnel(target_host, target_port)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        status = resp.status
        conn.close()
        return status, body

    def test_ca_cert_written(self):
        self.assertTrue(self.ca.ca_cert_path)
        self.assertTrue(os.path.exists(self.ca.ca_cert_path))
        with open(self.ca.ca_cert_path, "rb") as fh:
            self.assertIn(b"BEGIN CERTIFICATE", fh.read())

    def test_https_body_is_decrypted_and_recorded(self):
        status, body = self._https_through_proxy("127.0.0.1", self.oport, "/secret")
        self.assertEqual(status, 200)
        self.assertEqual(body, SECRET)
        # the decrypted HTTPS body is captured for the validator
        ex = self.proxy.transcript.body_for(
            f"https://127.0.0.1:{self.oport}/secret")
        self.assertIsNotNone(ex)
        self.assertIn("DB_PASSWORD", ex.body)
        self.assertTrue(ex.suspicious)          # the scan ran on the HTTPS body
        self.assertEqual(self.proxy.stats()["forwarded"], 1)

    def test_out_of_scope_connect_still_blocked_in_intercept_mode(self):
        resp = _raw_connect(self.proxy.address, f"{OUT_OF_SCOPE}:443")
        self.assertIn("403", resp.split("\r\n", 1)[0])
        self.assertTrue(any(h == OUT_OF_SCOPE for h, _ in self.blocks))

    def test_keep_alive_multiple_requests_on_one_tunnel(self):
        # a scanner reuses the TLS connection; both requests must be captured
        pu = urlsplit(self.proxy.address)
        cctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(pu.hostname, pu.port, context=cctx,
                                           timeout=10)
        conn.set_tunnel("127.0.0.1", self.oport)
        for path in ("/a", "/b"):
            conn.request("GET", path)
            conn.getresponse().read()
        conn.close()
        self.assertGreaterEqual(self.proxy.stats()["forwarded"], 2)


class TlsAvailabilityTest(unittest.TestCase):
    def test_make_ca_matches_availability(self):
        ca = tls_intercept.make_ca()
        if tls_intercept.AVAILABLE:
            self.assertIsNotNone(ca)
        else:
            self.assertIsNone(ca)   # graceful: caller falls back to tunnelling


if __name__ == "__main__":
    unittest.main()
