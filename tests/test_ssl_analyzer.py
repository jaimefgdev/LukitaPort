"""Point 2: certificates must be read even when verification is disabled."""

from datetime import datetime, timedelta, timezone

import pytest

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
    now = datetime.now(timezone.utc)
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
