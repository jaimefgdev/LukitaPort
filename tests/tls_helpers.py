"""
Helpers to build throwaway X.509 certificates and a loopback TLS server.

Everything binds to 127.0.0.1 on an ephemeral port chosen by the OS.
"""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def make_cert(
    cn: str,
    *,
    issuer_cert: x509.Certificate | None = None,
    issuer_key=None,
    org: str | None = None,
    sans: tuple[str, ...] = (),
    ca: bool = False,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
):
    """Return ``(cert, key)``; self-signed unless an issuer is given."""
    key  = ec.generate_private_key(ec.SECP256R1())
    now  = datetime.now(timezone.utc)
    subj = _name(cn, org)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer_cert.subject if issuer_cert else subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False,
        )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def write_pem(tmp: Path, stem: str, cert, key=None) -> tuple[Path, Path | None]:
    cert_path = tmp / f"{stem}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = None
    if key is not None:
        key_path = tmp / f"{stem}.key"
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path


class LoopbackTLSServer:
    """Accepts connections on 127.0.0.1 and completes TLS handshakes."""

    def __init__(self, cert_path: Path, key_path: Path) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert_path, key_path)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return                      # listening socket closed
            conn.settimeout(5)
            try:
                with self._ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)             # wait for the client to hang up
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.close()

    def __enter__(self) -> "LoopbackTLSServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._sock.close()
        self._thread.join(timeout=5)
