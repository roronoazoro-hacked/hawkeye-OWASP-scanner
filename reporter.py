import json
import io
import logging
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

log = logging.getLogger(__name__)

# ── Colour palette ────────────────────────────────────────────
C_BG       = colors.HexColor("#0a0e1a")
C_PANEL    = colors.HexColor("#0d1117")
C_BORDER   = colors.HexColor("#1e3a5f")
C_ACCENT   = colors.HexColor("#00b4d8")
C_TEXT     = colors.HexColor("#e0e6f0")
C_MUTED    = colors.HexColor("#6b7280")
C_CRITICAL = colors.HexColor("#ef4444")
C_HIGH     = colors.HexColor("#f97316")
C_MEDIUM   = colors.HexColor("#fbbf24")
C_LOW      = colors.HexColor("#4ade80")
C_INFO     = colors.HexColor("#93c5fd")
C_WHITE    = colors.white

SEV_COLOUR = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}

SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}

# ── Helpers ───────────────────────────────────────────────────

def _hex(color_obj):
    """
    FIX: ReportLab's HexColor has no .hexval() method.
    Convert a ReportLab color to a CSS hex string using its float r/g/b components.
    Works on all supported ReportLab versions (3.x and 4.x).
    """
    r = int(round(color_obj.red   * 255))
    g = int(round(color_obj.green * 255))
    b = int(round(color_obj.blue  * 255))
    return f"#{r:02x}{g:02x}{b:02x}"


def _risk_label(score):
    if score >= 40: return "CRITICAL"
    if score >= 20: return "HIGH"
    if score >= 10: return "MEDIUM"
    if score >  0:  return "LOW"
    return "CLEAN"


def _safe_str(val, max_len=None):
    """Coerce any value to a plain string, trimming if needed."""
    s = str(val) if val is not None else ""
    if max_len and len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def _styles():
    def s(name, **kw):
        return ParagraphStyle(name, **kw)
    return {
        "title":    s("title",    fontSize=22, textColor=C_ACCENT,   fontName="Helvetica-Bold",  spaceAfter=4),
        "subtitle": s("subtitle", fontSize=11, textColor=C_MUTED,    fontName="Helvetica",       spaceAfter=2),
        "h2":       s("h2",       fontSize=13, textColor=C_ACCENT,   fontName="Helvetica-Bold",  spaceBefore=14, spaceAfter=6),
        "h3":       s("h3",       fontSize=11, textColor=C_TEXT,     fontName="Helvetica-Bold",  spaceBefore=10, spaceAfter=4),
        "body":     s("body",     fontSize=9,  textColor=C_TEXT,     fontName="Helvetica",       spaceAfter=4,   leading=14),
        "muted":    s("muted",    fontSize=8,  textColor=C_MUTED,    fontName="Helvetica",       spaceAfter=2),
        "code":     s("code",     fontSize=7,  textColor=C_ACCENT,   fontName="Courier",         spaceAfter=2,   leading=10),
        "fix":      s("fix",      fontSize=9,  textColor=C_LOW,      fontName="Helvetica",       spaceAfter=4,   leading=13),
        "critical": s("critical", fontSize=9,  textColor=C_CRITICAL, fontName="Helvetica-Bold"),
        "high":     s("high",     fontSize=9,  textColor=C_HIGH,     fontName="Helvetica-Bold"),
        "medium":   s("medium",   fontSize=9,  textColor=C_MEDIUM,   fontName="Helvetica-Bold"),
        "low":      s("low",      fontSize=9,  textColor=C_LOW,      fontName="Helvetica-Bold"),
        "info":     s("info",     fontSize=9,  textColor=C_INFO,     fontName="Helvetica-Bold"),
    }


# ── PDF generator ─────────────────────────────────────────────

def generate_pdf(scan):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm,  bottomMargin=18*mm,
    )
    st    = _styles()
    W     = doc.width
    story = []

    all_findings = scan.get("findings", [])
    score        = scan.get("score", 0)
    risk         = _risk_label(score)

    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high     = [f for f in all_findings if f["severity"] == "HIGH"]
    medium   = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low_info = [f for f in all_findings if f["severity"] in ("LOW", "INFO")]

    # ── Cover / Executive Summary ─────────────────────────────
    story.append(Paragraph("VULNERABILITY ASSESSMENT REPORT", st["title"]))
    story.append(Paragraph(f"Target: {scan.get('url', '')}", st["subtitle"]))
    story.append(Paragraph(
        f"Scan ID: {scan.get('id', '')}  &nbsp;|&nbsp;  "
        f"Mode: {scan.get('mode', 'passive').upper()}  &nbsp;|&nbsp;  "
        f"Date: {scan.get('started', '')}",
        st["muted"]
    ))
    story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceAfter=10))
    story.append(Paragraph("Executive Summary", st["h2"]))

    # Risk score table
    # FIX: was colors.hexval() — replaced with _hex() helper
    risk_col  = SEV_COLOUR.get(risk, C_LOW)
    risk_hex  = _hex(risk_col)
    exec_data = [
        ["Overall Risk", "Score", "Critical", "High", "Medium", "Low / Info"],
        [
            Paragraph(f'<font color="{risk_hex}"><b>{risk}</b></font>', st["body"]),
            Paragraph(f'<b>{score}/100</b>', st["body"]),
            Paragraph(f'<font color="{_hex(C_CRITICAL)}"><b>{len(critical)}</b></font>', st["body"]),
            Paragraph(f'<font color="{_hex(C_HIGH)}"><b>{len(high)}</b></font>',         st["body"]),
            Paragraph(f'<font color="{_hex(C_MEDIUM)}"><b>{len(medium)}</b></font>',     st["body"]),
            Paragraph(f'<font color="{_hex(C_LOW)}"><b>{len(low_info)}</b></font>',      st["body"]),
        ]
    ]
    exec_tbl = Table(exec_data, colWidths=[W / 6] * 6)
    exec_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_PANEL),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_MUTED),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_PANEL, C_BG]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(exec_tbl)
    story.append(Spacer(1, 8))

    # Top 3 issues
    top3 = (critical + high + medium)[:3]
    if top3:
        story.append(Paragraph("Top Issues", st["h3"]))
        for i, f in enumerate(top3, 1):
            story.append(Paragraph(
                f'{i}. <b>{_safe_str(f.get("type"))}</b> — {_safe_str(f.get("url"))}',
                st["body"]
            ))
            story.append(Paragraph(_safe_str(f.get("detail")), st["muted"]))
            story.append(Paragraph(f'Fix: {_safe_str(f.get("fix"))}', st["fix"]))

    # Diff summary
    diff = scan.get("diff")
    if diff:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Change Summary vs Previous Scan", st["h3"]))
        story.append(Paragraph(
            f'Compared against scan <b>{diff["vs_scan_id"]}</b> ({diff["vs_started"]}): '
            f'<font color="{_hex(C_CRITICAL)}">+{diff["new"]} new</font>, '
            f'<font color="{_hex(C_LOW)}">-{diff["fixed"]} fixed</font>, '
            f'<font color="{_hex(C_MEDIUM)}">{diff["persisting"]} persisting</font>.',
            st["body"]
        ))

    story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceBefore=10, spaceAfter=10))

    # ── Technical Findings ────────────────────────────────────
    story.append(Paragraph("Technical Findings", st["h2"]))

    if not all_findings:
        story.append(Paragraph("No vulnerabilities detected.", st["body"]))
    else:
        for idx, f in enumerate(all_findings, 1):
            sev   = f.get("severity", "INFO")
            color = SEV_COLOUR.get(sev, C_INFO)
            # FIX: was color.hexval()[2:] — replaced with _hex()
            color_hex = _hex(color)

            # Finding header row
            hdr_data = [[
                Paragraph(f'<b>[{idx}] {_safe_str(f.get("type"))}</b>', st["body"]),
                Paragraph(f'<font color="{color_hex}"><b>{sev}</b></font>', st["body"]),
                Paragraph(f'CVSS {_safe_str(f.get("cvss", "N/A"))}',      st["muted"]),
                Paragraph(f'{_safe_str(f.get("cwe", "N/A"))}',             st["muted"]),
                Paragraph(f'Confidence {_safe_str(f.get("confidence", "?"))}%', st["muted"]),
            ]]
            hdr_tbl = Table(hdr_data, colWidths=[W * 0.38, W * 0.13, W * 0.13, W * 0.18, W * 0.18])
            hdr_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), C_PANEL),
                ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ]))
            story.append(hdr_tbl)

            # Detail rows
            detail_rows = [
                ("URL",    _safe_str(f.get("url"))),
                ("Detail", _safe_str(f.get("detail"))),
                ("OWASP",  _safe_str(f.get("owasp"))),
                ("Mode",   _safe_str(f.get("mode", "passive")).upper()),
                ("Fix",    _safe_str(f.get("fix"))),
            ]

            triage = f.get("triage")
            if triage and triage != "Unreviewed":
                detail_rows.append(("Triage", triage))

            cves = f.get("cve", [])
            if cves:
                detail_rows.append(("CVE(s)", ", ".join(cves)))

            signals = f.get("signals", [])
            if signals:
                detail_rows.append(("Signals", " | ".join(_safe_str(s) for s in signals)))

            evidence = f.get("evidence", {})
            if evidence.get("request"):
                detail_rows.append(("Request",  _safe_str(evidence["request"],  max_len=600)))
            if evidence.get("response"):
                detail_rows.append(("Response", _safe_str(evidence["response"], max_len=600)))

            # FIX: loop variable was named `r`, shadowing the HTTP response variable
            # used throughout checks.py. Renamed to `row_label` for clarity.
            det_tbl = Table(
                [
                    [
                        Paragraph(f'<b>{row_label}</b>', st["muted"]),
                        Paragraph(
                            row_value,
                            st["code"] if row_label in ("Request", "Response") else st["body"]
                        )
                    ]
                    for row_label, row_value in detail_rows
                ],
                colWidths=[W * 0.15, W * 0.85]
            )
            det_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, -1), C_BG),
                ("BACKGROUND",    (1, 0), (1, -1), C_PANEL),
                ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ]))
            story.append(det_tbl)
            story.append(Spacer(1, 6))

    # ── Footer ────────────────────────────────────────────────
    story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceBefore=10))
    story.append(Paragraph(
        f"Generated by OWASP Vulnerability Scanner — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        st["muted"]
    ))

    doc.build(story)
    return buf.getvalue()


# ── JSON export ───────────────────────────────────────────────

def export_json(scan):
    out = {
        "scan_id":  scan.get("id"),
        "url":      scan.get("url"),
        "mode":     scan.get("mode"),
        "started":  scan.get("started"),
        "finished": scan.get("finished"),
        "score":    scan.get("score"),
        "diff":     scan.get("diff"),
        "findings": scan.get("findings", []),
    }
    return json.dumps(out, indent=2, default=str)


# ── SARIF export ──────────────────────────────────────────────

def export_sarif(scan):
    """
    Produces a SARIF 2.1.0 file compatible with GitHub Advanced Security,
    Burp Suite, and Jira Security.

    FIX: evidence.payload key does not exist on findings — replaced with
    evidence.request which is the actual captured HTTP request string.
    """
    rules   = {}
    results = []

    level_map = {
        "CRITICAL": "error",
        "HIGH":     "error",
        "MEDIUM":   "warning",
        "LOW":      "note",
        "INFO":     "none",
    }

    for f in scan.get("findings", []):
        rule_id = f.get("cwe", "CWE-000").replace(" ", "-")

        if rule_id not in rules:
            cwe_num = rule_id.split("-")[-1]
            rules[rule_id] = {
                "id":               rule_id,
                "name":             f.get("type", "Unknown"),
                "shortDescription": {"text": f.get("type", "")},
                "fullDescription":  {"text": f.get("detail", "")},
                "helpUri":          f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "properties": {
                    "tags":     [f.get("owasp", ""), "security"],
                    "cvss":     str(f.get("cvss", "0.0")),
                    "severity": f.get("severity", "INFO"),
                },
            }

        # FIX: was evidence.get("payload", "") — "payload" key never existed.
        # The actual captured request is stored under evidence.request.
        evidence = f.get("evidence", {})
        captured_request = evidence.get("request", "")

        results.append({
            "ruleId":  rule_id,
            "level":   level_map.get(f.get("severity", "INFO"), "none"),
            "message": {"text": f.get("detail", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url", "")},
                }
            }],
            "properties": {
                "confidence":       f.get("confidence", 0),
                "triage":           f.get("triage", "Unreviewed"),
                "signals":          f.get("signals", []),
                "cve":              f.get("cve", []),
                "captured_request": captured_request[:500] if captured_request else "",
                "scan_mode":        f.get("mode", "passive"),
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           "OWASP Vulnerability Scanner",
                    "version":        "2.0.0",
                    "informationUri": "https://owasp.org",
                    "rules":          list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "scan_id":  scan.get("id"),
                "url":      scan.get("url"),
                "started":  scan.get("started"),
                "finished": scan.get("finished"),
                "score":    scan.get("score"),
            }
        }]
    }
    return json.dumps(sarif, indent=2, default=str)

# ── CSV export ────────────────────────────────────────────────

def export_csv(scan):
    import csv
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Severity", "Title", "OWASP", "CWE", "CVSS",
        "Confidence", "URL", "Detail", "Fix", "Mode",
        "Triage", "CVE", "Signals"
    ])

    for f in scan.get("findings", []):
        writer.writerow([
            f.get("severity", ""),
            f.get("type", ""),
            f.get("owasp", ""),
            f.get("cwe", ""),
            f.get("cvss", ""),
            f.get("confidence", ""),
            f.get("url", ""),
            f.get("detail", ""),
            f.get("fix", ""),
            f.get("mode", ""),
            f.get("triage", "Unreviewed"),
            ", ".join(f.get("cve", [])),
            " | ".join(f.get("signals", [])),
        ])

    return output.getvalue()