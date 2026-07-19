"""
Subsystem 6 — PDF audit report generator for Project Sentry ASEAN.

Called on every BLOCK verdict. Produces a cited PDPA compliance record
for the security officer.
"""

import logging
import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle)

logger = logging.getLogger(__name__)

REPORTS_DIR = "/reports"
WATERMARK = "PROJECT SENTRY ASEAN — AUTOMATED COMPLIANCE RECORD"


def _watermark(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawCentredString(A4[0] / 2, 10 * mm, WATERMARK)
    canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()

def _fmt_pii(event):
    """PII entities with Presidio confidence, one per line."""
    types = event.get("pii_types", [])
    scores = event.get("pii_scores", {})
    if not types:
        return "none"
    lines = []
    for t in types:
        s = scores.get(t)
        if s is None:
            lines.append(t)
        elif s < 0.7:
            lines.append(f"{t} — {s:.2f} (low confidence)")
        else:
            lines.append(f"{t} — {s:.2f}")
    return "<br/>".join(lines)

def _fmt_sensitivity(event):
    s = (event.get("sensitivity") or "n/a").lower()
    color = {"high": "#8a2018", "medium": "#a8721a", "low": "#1f4b3f"}.get(s, "#333333")
    return f'<font color="{color}"><b>{s.upper()}</b></font>'

def generate_report(event: dict) -> str:
    """
    Build a PDF audit report from an enforcement event.

    Expected keys: event_id, timestamp, source, dest_ip, jurisdiction,
    content_type, pii_types, sensitivity, pdpa_clause, justification, verdict
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    event_id = event.get("event_id", "unknown")
    ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    # Human-readable version for display (keep `ts` raw for the filename).
    try:
        _dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ts_display = _dt.strftime("%d %B %Y, %H:%M:%S UTC")
    except Exception:
        ts_display = ts
    safe_ts = ts.replace(":", "-").replace(".", "-")
    path = os.path.join(REPORTS_DIR, f"report_{event_id}_{safe_ts}.pdf")

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16,
                        textColor=colors.HexColor("#8B0000"))
    body = styles["BodyText"]

    story = [
        Paragraph("PDPA Compliance Enforcement Report", h1),
        Paragraph(f"Event ID: <b>{event_id}</b>", body),
        Spacer(1, 6 * mm),
    ]

    rows = [
        ["Field", "Value"],
        ["Timestamp", ts_display],
        ["Enforcement action", event.get("verdict", "BLOCK")],
        ["Source workload", event.get("source", "n/a")],
        ["Destination", event.get("dest_ip", "n/a")],
        ["Jurisdiction", event.get("jurisdiction", "n/a")],
        ["Content type inspected",
         Paragraph((event.get("content_type", "n/a") or "n/a").split(";")[0], body)],
        ["PII detected", Paragraph(_fmt_pii(event), body)],
        ["Content sensitivity", Paragraph(_fmt_sensitivity(event), body)],
        ["PDPA clause cited", event.get("pdpa_clause", "n/a")],
    ]
    table = Table(rows, colWidths=[50 * mm, 110 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [table, Spacer(1, 2 * mm)]

    legend_tbl = Table([
        ["Confidence", "0.85 – 0.95", "exact pattern match"],
        ["", "0.55 – 0.65", "OCR-corrected, NRIC checksum unverified"],
        ["Sensitivity", "HIGH", "strong identifiers (e.g. NRIC)"],
        ["", "MEDIUM", "name / contact data"],
        ["", "LOW", "incidental references"],
    ], colWidths=[26 * mm, 24 * mm, 90 * mm], hAlign="LEFT")
    legend_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#555555")),
        ("FONTNAME", (0, 0), (1, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        # colour the sensitivity values to match the report body
        ("TEXTCOLOR", (1, 2), (1, 2), colors.HexColor("#8a2018")),  # high  = red
        ("TEXTCOLOR", (1, 3), (1, 3), colors.HexColor("#a8721a")),  # medium = amber
        ("TEXTCOLOR", (1, 4), (1, 4), colors.HexColor("#1f4b3f")),  # low   = green
    ]))
    story += [
        legend_tbl,
        Spacer(1, 2 * mm),
        Paragraph("Legal Justification", styles["Heading2"]),
        Paragraph(event.get("justification") or "Justification unavailable.", body),
        Spacer(1, 4 * mm),
        Paragraph("Remediation", styles["Heading2"]),
        Paragraph(
            "This transfer was blocked under the PDPA Transfer Limitation "
            "Obligation. To proceed lawfully, the Data Protection Officer must "
            "verify that a documented safeguard is in place for the destination "
            "jurisdiction (comparable-protection contract, binding corporate "
            "rules, ASEAN Model Contractual Clauses, or a recognised "
            "certification), or that a valid exception applies. Consent and "
            "business-purpose determination remain a human DPO responsibility "
            "and are outside this system's scope.",
            body),
    ]

    doc = SimpleDocTemplate(path, pagesize=A4,
                            topMargin=20 * mm, bottomMargin=20 * mm,
                            leftMargin=20 * mm, rightMargin=20 * mm,
                            title=f"Sentry ASEAN Report {event_id}")
    doc.build(story, onFirstPage=_watermark, onLaterPages=_watermark)

    logger.info("Audit report written: %s", path)
    return path
