"""Point 2: certificates must be read even when verification is disabled."""

import ssl
import warnings
from datetime import UTC, datetime, timedelta

import pytest

import ssl_analyzer
from ssl_analyzer import analyze_ssl, analyze_ssl_for_ports
from tls_helpers import LoopbackTLSServer, make_cert, write_pem


@pytest.fixture
def ca(tmp_path):
    cert, key = make_cert("LukitaPort Test CA", org="Test CA Org", ca=True)
    ca_path, _ = write_pem(tmp_path, "ca", cert)
    return cert, key, ca_path


def test_self_signed_certificate_is_parsed(tmp_path):
    cert, key = make_cert("localhost", org="Self Org", sans=("localhost",))
    with LoopbackTLSServer(*write_pem(tmp_path, "leaf", cert, key)) as srv:
        res = analyze_ssl("127.0.0.1", srv.port, timeout=3)

    assert res["error"] is None
    assert res["valid"] is True
    assert res["subject"]["commonName"] == "localhost"
    assert res["issuer"]["organizationName"] == "Self Org"
    assert res["sans"] == ["localhost"]
    assert res["self_signed"] is True
    assert res["trusted"] is False
    assert res["verify_error"]
    assert "Self-signed certificate" in res["issues"]
    assert res["protocol"] in ("TLSv1.2", "TLSv1.3")
    assert res["cipher"] and res["bits"]
    assert 88 <= res["days_until_expiry"] <= 90
    assert res["grade"] == "C"


def test_ca_signed_certificate_is_trusted(tmp_path, ca):
    ca_cert, ca_key, ca_path = ca
    cert, key = make_cert(
        "localhost", issuer_cert=ca_cert, issuer_key=ca_key, sans=("localhost",),
    )
    with LoopbackTLSServer(*write_pem(tmp_path, "leaf", cert, key)) as srv:
        res = analyze_ssl("localhost", srv.port, timeout=3, cafile=str(ca_path))

    assert res["valid"] is True
    assert res["trusted"] is True
    assert res["verify_error"] is None
    assert res["self_signed"] is False
    assert res["issuer"] == {"organizationName": "Test CA Org", "commonName": "LukitaPort Test CA"}
    assert not any("not trusted" in i for i in res["issues"])


def test_hostname_mismatch_is_not_trusted(tmp_path, ca):
    ca_cert, ca_key, ca_path = ca
    cert, key = make_cert(
        "other.test", issuer_cert=ca_cert, issuer_key=ca_key, sans=("other.test",),
    )
    with LoopbackTLSServer(*write_pem(tmp_path, "leaf", cert, key)) as srv:
        res = analyze_ssl("localhost", srv.port, timeout=3, cafile=str(ca_path))

    assert res["valid"] is True
    assert res["trusted"] is False
    assert any("not trusted" in i for i in res["issues"])


def test_expired_certificate_grades_f(tmp_path):
    now = datetime.now(UTC)
    cert, key = make_cert(
        "localhost", not_before=now - timedelta(days=30), not_after=now - timedelta(days=2),
    )
    with LoopbackTLSServer(*write_pem(tmp_path, "leaf", cert, key)) as srv:
        res = analyze_ssl("127.0.0.1", srv.port, timeout=3)

    assert res["expired"] is True
    assert res["days_until_expiry"] < 0
    assert "Certificate is EXPIRED" in res["issues"]
    assert res["grade"] == "F"


def test_connection_refused_is_reported():
    # Bind then close to obtain a loopback port with nothing listening.
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    res = analyze_ssl("127.0.0.1", port, timeout=2)
    assert res["valid"] is False
    assert res["error"]


def test_analyze_for_ports_only_https_ports():
    assert analyze_ssl_for_ports("127.0.0.1", [22, 80]) == {
        "error": "No HTTPS ports detected", "results": {},
    }


# ── Point 18: TLS version probing ─────────────────────────────────────────────


@pytest.fixture
def leaf(tmp_path):
    cert, key = make_cert("localhost", sans=("localhost",))
    return write_pem(tmp_path, "leaf", cert, key)


def test_tls12_only_server(leaf):
    with LoopbackTLSServer(*leaf, minimum_version=ssl.TLSVersion.TLSv1_2,
                           maximum_version=ssl.TLSVersion.TLSv1_2) as srv:
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            accepted, untested = ssl_analyzer._probe_tls_versions("127.0.0.1", srv.port, 3)
    assert accepted == ["TLSv1.2"]
    assert "TLSv1.2" not in untested and "TLSv1.3" not in untested


def test_tls13_only_server(leaf):
    with LoopbackTLSServer(*leaf, minimum_version=ssl.TLSVersion.TLSv1_3) as srv:
        accepted, _ = ssl_analyzer._probe_tls_versions("127.0.0.1", srv.port, 3)
    assert accepted == ["TLSv1.3"]


def _local_openssl_can_serve_tls10(leaf) -> bool:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with LoopbackTLSServer(*leaf, minimum_version=ssl.TLSVersion.TLSv1,
                                   maximum_version=ssl.TLSVersion.TLSv1,
                                   ciphers="DEFAULT:@SECLEVEL=0") as srv:
                return ssl_analyzer._accepts_version(
                    "127.0.0.1", srv.port, 3, "TLSv1.0", "TLSv1", None)
    except (ssl.SSLError, ValueError):
        return False


def test_legacy_tls10_is_detected(leaf):
    if not _local_openssl_can_serve_tls10(leaf):
        pytest.skip("this OpenSSL build cannot negotiate TLS 1.0 at all")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with LoopbackTLSServer(*leaf, minimum_version=ssl.TLSVersion.TLSv1,
                               ciphers="DEFAULT:@SECLEVEL=0") as srv:
            accepted, _ = ssl_analyzer._probe_tls_versions("127.0.0.1", srv.port, 3)
    assert "TLSv1.0" in accepted


def test_versions_client_cannot_offer_are_untested(leaf, monkeypatch):
    monkeypatch.setattr(ssl, "HAS_TLSv1", False)
    monkeypatch.setattr(ssl, "HAS_TLSv1_1", False)
    with LoopbackTLSServer(*leaf) as srv:
        res = analyze_ssl("127.0.0.1", srv.port, timeout=3)
    assert res["tls_versions_untested"] == ["TLSv1.1", "TLSv1.0"]
    assert "TLSv1.0" not in res["tls_versions_offered"]
