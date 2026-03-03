import io
from datetime import datetime
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, Image,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

C_BG     = colors.HexColor("#050505")
C_CARD   = colors.HexColor("#0f0f0f")
C_ACCENT = colors.HexColor("#ff0033")
C_GREEN  = colors.HexColor("#00cc66")
C_YELLOW = colors.HexColor("#ffaa00")
C_RED    = colors.HexColor("#ff4444")
C_TEXT   = colors.HexColor("#f0f0f0")
C_MUTED  = colors.HexColor("#888888")
C_BORDER = colors.HexColor("#333333")
C_DARK   = colors.HexColor("#111111")
C_WHITE  = colors.white


def make_styles():
    styles = {}
    styles["title"]    = ParagraphStyle("title",    fontName="Helvetica-Bold", fontSize=28, textColor=C_ACCENT, spaceAfter=4, leading=32)
    styles["subtitle"] = ParagraphStyle("subtitle", fontName="Helvetica",      fontSize=10, textColor=C_MUTED,  spaceAfter=18, letterSpacing=2)
    styles["section"]  = ParagraphStyle("section",  fontName="Helvetica-Bold", fontSize=9,  textColor=C_MUTED,  spaceBefore=18, spaceAfter=8, letterSpacing=2)
    styles["body"]     = ParagraphStyle("body",     fontName="Helvetica",      fontSize=9,  textColor=C_TEXT,   leading=14, spaceAfter=4)
    styles["mono"]     = ParagraphStyle("mono",     fontName="Courier",        fontSize=8,  textColor=C_TEXT,   leading=12)
    styles["label"]    = ParagraphStyle("label",    fontName="Helvetica-Bold", fontSize=8,  textColor=C_MUTED,  letterSpacing=1)
    styles["accent"]   = ParagraphStyle("accent",   fontName="Helvetica-Bold", fontSize=9,  textColor=C_ACCENT)
    styles["green"]    = ParagraphStyle("green",    fontName="Helvetica-Bold", fontSize=9,  textColor=C_GREEN)
    styles["small"]    = ParagraphStyle("small",    fontName="Helvetica",      fontSize=7.5, textColor=C_MUTED, leading=11)
    return styles


def _risk_color(risk: str) -> colors.Color:
    return {"high": C_ACCENT, "medium": C_YELLOW, "low": C_GREEN, "info": C_MUTED}.get(risk, C_MUTED)


def _state_color(state: str) -> colors.Color:
    return {"open": C_GREEN, "closed": C_RED, "filtered": C_YELLOW}.get(state, C_MUTED)


from config import PORT_RISK

def generate_pdf(scan_data: dict, audit_data: Optional[dict] = None, screenshot_png: Optional[bytes] = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm)

    styles  = make_styles()
    story   = []
    ts      = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    meta    = scan_data.get("meta", {})
    results = scan_data.get("results", [])
    summary = scan_data.get("summary", {})

    story.append(Paragraph("LukitaPort", styles["title"]))
    story.append(Paragraph("PORT SCAN REPORT", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=14))

    if screenshot_png:
        try:
            img = Image(io.BytesIO(screenshot_png), width=174*mm, height=80*mm)
            img.hAlign = "CENTER"
            story.append(Paragraph("WEB SCREENSHOT", styles["section"]))
            story.append(img)
            story.append(Spacer(1, 10))
        except Exception:
            pass

    story.append(Paragraph("SCAN METADATA", styles["section"]))
    target_info = meta.get("target", {}) or {}
    geo         = target_info.get("geo") or {}

    meta_rows = [
        ["Target",      target_info.get("input", "—")],
        ["Resolved IP", target_info.get("ip", "—")],
        ["Hostname",    target_info.get("hostname") or "—"],
        ["Scan mode",   target_info.get("mode", "—")],
        ["Profile",     target_info.get("profile", "normal")],
        ["Total ports", str(summary.get("total", "—"))],
        ["Generated",   ts],
    ]
    if geo:
        if geo.get("country"):
            meta_rows.append(["Location", f"{geo.get('city','')} · {geo.get('country','')} · {geo.get('country_code','')}"])
        if geo.get("isp"):
            meta_rows.append(["ISP", geo.get("isp", "")])
        if geo.get("asn"):
            meta_rows.append(["ASN", geo.get("asn", "")])

    meta_table = Table(meta_rows, colWidths=[40*mm, 130*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",       (0, 0), (-1, -1), "Courier"),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",      (0, 0), (0, -1), C_MUTED),
        ("TEXTCOLOR",      (1, 0), (1, -1), C_TEXT),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_CARD]),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("GRID",           (0, 0), (-1, -1), 0.3, C_BORDER),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("RESULTS SUMMARY", styles["section"]))
    card_data = [[
        Paragraph(f'<font size="22"><b>{summary.get("open", 0)}</b></font><br/><font size="7">OPEN</font>',     styles["green"]),
        Paragraph(f'<font size="22"><b>{summary.get("closed", 0)}</b></font><br/><font size="7">CLOSED</font>', styles["body"]),
        Paragraph(f'<font size="22"><b>{summary.get("filtered", 0)}</b></font><br/><font size="7">FILTERED</font>', styles["body"]),
        Paragraph(f'<font size="22"><b>{summary.get("total", 0)}</b></font><br/><font size="7">TOTAL</font>',   styles["accent"]),
    ]]
    card_table = Table(card_data, colWidths=[42*mm, 42*mm, 42*mm, 42*mm])
    card_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, 0), colors.HexColor("#001a0d")),
        ("BACKGROUND",  (1, 0), (1, 0), C_DARK),
        ("BACKGROUND",  (2, 0), (2, 0), colors.HexColor("#1a1000")),
        ("BACKGROUND",  (3, 0), (3, 0), colors.HexColor("#1a000a")),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BOX",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEBEFORE",  (1, 0), (-1, 0), 0.5, C_BORDER),
        ("TEXTCOLOR",   (0, 0), (0, 0), C_GREEN),
        ("TEXTCOLOR",   (2, 0), (2, 0), C_YELLOW),
        ("TEXTCOLOR",   (3, 0), (3, 0), C_ACCENT),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 18))

    open_results = [r for r in results if r.get("state") == "open"]
    if open_results:
        high_n = sum(1 for r in open_results if PORT_RISK.get(r.get("port"), "info") == "high")
        med_n  = sum(1 for r in open_results if PORT_RISK.get(r.get("port"), "info") == "medium")
        low_n  = sum(1 for r in open_results if PORT_RISK.get(r.get("port"), "info") == "low")
        risk_rows = [[
            Paragraph(f"● HIGH RISK: {high_n} ports",   ParagraphStyle("rh", fontName="Courier-Bold", fontSize=8, textColor=C_ACCENT)),
            Paragraph(f"● MEDIUM RISK: {med_n} ports",  ParagraphStyle("rm", fontName="Courier-Bold", fontSize=8, textColor=C_YELLOW)),
            Paragraph(f"● LOW RISK: {low_n} ports",     ParagraphStyle("rl", fontName="Courier-Bold", fontSize=8, textColor=C_GREEN)),
        ]]
        risk_table = Table(risk_rows, colWidths=[56*mm, 56*mm, 56*mm])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (0, 0), colors.HexColor("#200008")),
            ("BACKGROUND",  (1, 0), (1, 0), colors.HexColor("#1a1000")),
            ("BACKGROUND",  (2, 0), (2, 0), colors.HexColor("#001a0a")),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",  (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("BOX",         (0, 0), (-1, -1), 0.5, C_BORDER),
            ("LINEBEFORE",  (1, 0), (-1, 0), 0.5, C_BORDER),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 18))

    story.append(Paragraph("ALL RESULTS", styles["section"]))
    headers_row = [
        Paragraph("PORT",             styles["label"]),
        Paragraph("STATE",            styles["label"]),
        Paragraph("SERVICE",          styles["label"]),
        Paragraph("RISK",             styles["label"]),
        Paragraph("RESPONSE",         styles["label"]),
        Paragraph("VERSION / BANNER", styles["label"]),
    ]
    rows = [headers_row]

    risk_map  = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "—"}
    state_map = {"open": "Open", "closed": "Closed", "filtered": "Filtered"}

    for r in results:
        port    = r.get("port", "")
        state   = r.get("state", "")
        risk    = PORT_RISK.get(port, "info") if state == "open" else "info"
        version = str((r.get("version") or r.get("banner") or ""))[:40]
        rows.append([
            Paragraph(str(port), styles["mono"]),
            Paragraph(state_map.get(state, state), ParagraphStyle("s",  fontName="Courier-Bold", fontSize=7.5, textColor=_state_color(state))),
            Paragraph(r.get("service", ""), styles["mono"]),
            Paragraph(risk_map.get(risk, "—"), ParagraphStyle("rk", fontName="Courier-Bold", fontSize=7.5, textColor=_risk_color(risk))),
            Paragraph(f"{r.get('response_time_ms')} ms" if r.get("response_time_ms") is not None else "—", styles["small"]),
            Paragraph(version, styles["small"]),
        ])

    results_table = Table(rows, colWidths=[18*mm, 20*mm, 28*mm, 18*mm, 22*mm, 62*mm], repeatRows=1)
    results_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_DARK, C_CARD]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, C_ACCENT),
    ]))
    story.append(results_table)
    story.append(Spacer(1, 20))

    if audit_data:
        headers_audit = audit_data.get("headers")
        if headers_audit and not headers_audit.get("error"):
            story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=10))
            story.append(Paragraph("HTTP SECURITY HEADERS AUDIT", styles["section"]))
            grade       = headers_audit.get("grade", "?")
            score       = headers_audit.get("score", 0)
            grade_color = {"A": C_GREEN, "B": C_GREEN, "C": C_YELLOW, "D": C_YELLOW, "F": C_ACCENT}.get(grade, C_MUTED)
            story.append(Paragraph(f'<font size="20"><b>{grade}</b></font>  <font size="9">Score: {score}/100</font>',
                                   ParagraphStyle("gp", fontName="Courier-Bold", fontSize=20, textColor=grade_color, leading=24)))
            story.append(Spacer(1, 8))

            missing = headers_audit.get("missing", [])
            if missing:
                story.append(Paragraph("Missing headers:", styles["label"]))
                miss_rows = [["HEADER", "SEVERITY", "DESCRIPTION"]]
                for h in missing:
                    miss_rows.append([
                        Paragraph(h["header"], styles["mono"]),
                        Paragraph(h["severity"].upper(), ParagraphStyle("sv", fontName="Courier-Bold", fontSize=7.5, textColor=_risk_color(h["severity"]))),
                        Paragraph(h.get("description_en", ""), styles["small"]),
                    ])
                miss_table = Table(miss_rows, colWidths=[55*mm, 22*mm, 91*mm])
                miss_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
                    ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_DARK, C_CARD]),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
                    ("LINEBELOW",     (0, 0), (-1, 0), 1, C_ACCENT),
                ]))
                story.append(Spacer(1, 4))
                story.append(miss_table)
                story.append(Spacer(1, 12))

            dangerous = headers_audit.get("dangerous", [])
            if dangerous:
                story.append(Paragraph("Information disclosure headers (should be removed):", styles["label"]))
                for h in dangerous:
                    story.append(Paragraph(f'<b>{h["header"]}:</b> {h["value"]} — {h["description"]}',
                                           ParagraphStyle("dh", fontName="Courier", fontSize=7.5, textColor=C_YELLOW, spaceAfter=3)))
                story.append(Spacer(1, 10))

        tech_data = audit_data.get("technologies")
        if tech_data and not tech_data.get("error") and tech_data.get("technologies"):
            story.append(Paragraph("DETECTED TECHNOLOGIES", styles["section"]))
            techs = tech_data["technologies"]
            tech_rows_data = []
            for i in range(0, len(techs), 3):
                row = []
                for j in range(3):
                    if i + j < len(techs):
                        t = techs[i + j]
                        row.append(Paragraph(f'{t["icon"]} <b>{t["name"]}</b><br/><font size="7">{t["category"]}</font>',
                                             ParagraphStyle("tt", fontName="Helvetica", fontSize=8.5, textColor=C_TEXT, leading=13)))
                    else:
                        row.append(Paragraph("", styles["body"]))
                tech_rows_data.append(row)
            tech_table = Table(tech_rows_data, colWidths=[56*mm, 56*mm, 56*mm])
            tech_table.setStyle(TableStyle([
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_CARD]),
                ("TOPPADDING",    (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
            ]))
            story.append(tech_table)
            story.append(Spacer(1, 12))

        paths_data = audit_data.get("paths")
        if paths_data and paths_data.get("found"):
            story.append(Paragraph("SENSITIVE PATHS DISCOVERED", styles["section"]))
            all_found = [f for f in paths_data["found"] if f["accessible"]] + [f for f in paths_data["found"] if not f["accessible"]]
            path_rows = [["PATH", "LABEL", "SEVERITY", "STATUS"]]
            for f in all_found:
                path_rows.append([
                    Paragraph(f["path"], styles["mono"]),
                    Paragraph(f["label"], styles["small"]),
                    Paragraph(f["severity"].upper(), ParagraphStyle("ps", fontName="Courier-Bold", fontSize=7.5, textColor=_risk_color(f["severity"]))),
                    Paragraph(str(f["status_code"]), styles["mono"]),
                ])
            path_table = Table(path_rows, colWidths=[48*mm, 48*mm, 26*mm, 46*mm])
            path_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_DARK, C_CARD]),
                ("TOPPADDING",    (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
                ("LINEBELOW",     (0, 0), (-1, 0), 1, C_ACCENT),
            ]))
            story.append(path_table)
            story.append(Spacer(1, 12))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))
    story.append(Paragraph(f"LukitaPort  ·  jaimefg1888  ·  For educational use only  ·  {ts}",
                           ParagraphStyle("ft", fontName="Courier", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER)))

    doc.build(story)
    return buf.getvalue()
