"""Point 10: exported reports must not be injectable by scan data."""

import io

import main
import pdf_generator
from scan_service import build_markdown_report

EVIL = '<b>boom</font> | `x` [link](http://e.test) <script>alert(1)</script>\nnext'


def _scan(results):
    return {"meta": {"target": {"input": EVIL, "ip": "127.0.0.1"}},
            "results": results,
            "summary": {"open": 1, "closed": 0, "filtered": 0, "total": 1}}


def test_pdf_survives_markup_in_banners():
    data = _scan([{"port": 80, "state": "open", "service": EVIL, "banner": EVIL}])
    audit = {
        "headers": {"grade": EVIL, "score": 1,
                    "missing": [{"header": EVIL, "severity": "high", "description_en": EVIL}],
                    "dangerous": [{"header": "Server", "value": EVIL, "description": EVIL}]},
        "technologies": {"technologies": [{"icon": EVIL, "name": EVIL, "category": EVIL}]},
        "paths": {"found": [{"path": EVIL, "label": EVIL, "severity": "high",
                             "status_code": 200, "accessible": True}]},
    }
    pdf = pdf_generator.generate_pdf(data, audit)
    assert pdf.startswith(b"%PDF")


def test_pdf_escape_helper():
    assert pdf_generator._esc("<a>&") == "&lt;a&gt;&amp;"
    assert pdf_generator._esc(None) == ""


def test_markdown_escapes_injection():
    md = build_markdown_report(
        meta={"target": {"input": EVIL, "ip": "1.2.3.4"}},
        results=[{"port": 80, "state": "open", "service": EVIL, "banner": EVIL}],
        summary={"open": 1, "closed": 0, "filtered": 0, "total": 1},
    )
    assert "<script>" not in md
    assert "&lt;script&gt;" in md
    assert "[link](" not in md
    for line in md.splitlines():
        if line.startswith("| 80 |"):
            # Exactly the 6 table pipes; the banner's pipe is escaped.
            assert line.replace("\\|", "").count("|") == 6
    assert "\nnext" not in md


def test_pdf_error_does_not_leak_details(app_client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internal path /opt/x")

    monkeypatch.setattr(pdf_generator, "generate_pdf", boom)
    resp = app_client.post("/api/export/pdf", json={"scan": {"meta": {}, "results": [], "summary": {}}})
    assert resp.status_code == 500
    assert "secret" not in resp.text
