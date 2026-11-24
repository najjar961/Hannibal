"""Optional TLS interception for the scope proxy (Phase 2).

Phase 1 (proxy.py) enforces scope on an HTTPS CONNECT by its destination host,
then tunnels the encrypted bytes untouched — so it never sees HTTPS response
bodies. Phase 2 adds opt-in man-in-the-middle interception: the proxy terminates
the client's TLS with a leaf certificate it mints on the fly for the requested
host (signed by an ephemeral per-run CA), opens its own TLS connection to the
real upstream, and reads the decrypted HTTP in between. That lets the validator
corroborate an HTTPS detection against the real response body, exactly as it
already does for plain HTTP.

This is the piece that needs a dependency: minting X.509 leaf certificates needs
`cryptography`, which the stdlib does not provide. It stays strictly optional —
the core tool and Phase 1 are stdlib-only. If `cryptography` is missing,
`make_ca` returns None and the proxy falls back to Phase-1 tunnelling instead of
failing.

Scope is unchanged. Interception only ever happens for a host the scope guard
has already allowed (the CONNECT is scope-checked first), and the decrypted
requests are re-checked against the same guard. The CA is generated fresh each
run, held in memory, and its certificate is written to the run directory so you
can inspect or trust it; the private key never leaves the process.

The ProjectDiscovery scanners (httpx, nuclei, katana) do not verify TLS against
the system trust store by default, so interception works without installing the
CA anywhere. A client that *does* verify can be pointed at the written CA cert.
"""
from __future__ import annotations

import ipaddress
import os
import re
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    AVAILABLE = True
except ImportError:              # optional dependency — Phase 1 works without it
    AVAILABLE = False

_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


def _safe(host: str) -> str:
    return _UNSAFE.sub("_", host) or "host"


class CertAuthority:
    """An ephemeral CA that mints (and caches) per-host leaf certs for the
    proxy to terminate client TLS with. One per run; keys live only in memory
    and a private temp dir."""

    def __init__(self, workdir: Optional[str] = None):
        if not AVAILABLE:
            raise RuntimeError("cryptography is required for TLS interception")
        self._lock = threading.Lock()
        self._contexts: Dict[str, ssl.SSLContext] = {}
        self._tmpdir = tempfile.mkdtemp(prefix="hannibal-ca-")
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._cert = self._build_ca_cert(self._key)
        self.ca_cert_path = self._write_ca_cert(workdir)

    def _build_ca_cert(self, key):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Hannibal Scope Proxy CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               "Hannibal (authorized testing only)"),
        ])
        now = datetime.now(timezone.utc)
        return (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                               critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))

    def _write_ca_cert(self, workdir: Optional[str]) -> str:
        pem = self._cert.public_bytes(serialization.Encoding.PEM)
        for target in (os.path.join(workdir, "hannibal-proxy-ca.pem") if workdir
                       else None,
                       os.path.join(self._tmpdir, "hannibal-proxy-ca.pem")):
            if not target:
                continue
            try:
                os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(pem)
                return target
            except OSError:
                continue
        return ""

    def context_for(self, host: str) -> ssl.SSLContext:
        """A server-side SSLContext presenting a freshly-minted leaf for host."""
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
            cert_pem, key_pem = self._mint_leaf(host)
            cpath = os.path.join(self._tmpdir, f"{_safe(host)}.crt")
            kpath = os.path.join(self._tmpdir, f"{_safe(host)}.key")
            with open(cpath, "wb") as fh:
                fh.write(cert_pem)
            with open(kpath, "wb") as fh:
                fh.write(key_pem)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cpath, kpath)
            self._contexts[host] = ctx
            return ctx

    def _mint_leaf(self, host: str) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                .issuer_name(self._cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .sign(self._key, hashes.SHA256()))
        return (cert.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


def make_ca(workdir: Optional[str] = None) -> Optional[CertAuthority]:
    """A CertAuthority if `cryptography` is installed, else None (caller then
    falls back to Phase-1 tunnelling)."""
    if not AVAILABLE:
        return None
    return CertAuthority(workdir)
