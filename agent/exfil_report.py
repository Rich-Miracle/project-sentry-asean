"""
Attempted Exfiltration — Egress Audit report generator for Project Sentry ASEAN.

Parses EGRESS_BLOCKED events from the controller log and produces a DPO-facing
PDF audit of egress attempts blocked at the kernel gate over a period.

An EGRESS_BLOCKED line is emitted by the controller for any flow that reached
the reassembler (i.e. was NOT on the infra allowlist) and moved zero bytes to
its destination — a flow that tried to leave to a non-sanctioned destination
and was dropped at the eBPF egress hook. Zero bytes left the host.

Usage:
    python3 exfil_report.py --period day
    python3 exfil_report.py --period week
    python3 exfil_report.py --period month
    python3 exfil_report.py --log /var/log/sentry/controller.log --period week
"""
import argparse
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle)

REPORTS_DIR = os.environ.get("SENTRY_REPORTS_DIR", "/reports")
DEFAULT_LOG = os.environ.get("SENTRY_CONTROLLER_LOG",
                             "/var/log/sentry/controller.log")
WATERMARK = "PROJECT SENTRY ASEAN — AUTOMATED COMPLIANCE RECORD"

# Matches lines like:
# 2026/08/14 23:40:34.219931 EGRESS_BLOCKED src=172.30.0.30:40618 \
#   dst=192.168.37.129:4444 proto=TCP reason=not-sanctioned via=FIN
_LINE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\.\d+\s+"
    r"EGRESS_BLOCKED\s+src=(?P<src>[\d.]+:\d+)\s+dst=(?P<dst>[\d.]+:\d+)\s+"
    r"proto=(?P<proto>\w+)\s+reason=(?P<reason>[\w-]+)\s+via=(?P<via>\w+)"
)

_PERIODS = {"day": 1, "week": 7, "month": 30}


def _watermark(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawCentredString(A4[0] / 2, 10 * mm, WATERMARK)
    canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _parse(logpath, since):
    """Return list of event dicts newer than `since` (naive local datetime)."""
    events = []
    if not os.path.exists(logpath):
        return events
    with open(logpath, "r", errors="ignore") as fh:
        for line in fh:
            m = _LINE.search(line)
            if not m:
                continue
            try:
                dt = datetime.strptime(
                    f"{m.group('date')} {m.group('time')}",
                    "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
            if dt < since:
                continue
            events.append({
                "dt": dt,
                "src": m.group("src"),
                "dst": m.group("dst"),
                "proto": m.group("proto"),
                "reason": m.group("reason"),
                "via": m.group("via"),
            })
    return events


def generate(period="week", logpath=DEFAULT_LOG):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    days = _PERIODS.get(period, 7)
    since = datetime.now() - timedelta(days=days)
    events = _parse(logpath, since)

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(REPORTS_DIR, f"exfil_report_{period}_{stamp}.pdf")

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16,
                        textColor=colors.HexColor("#8a2018"))
    body = styles["BodyText"]

    period_label = {"day": "Last 24 hours", "week": "Last 7 days",
                    "month": "Last 30 days"}.get(period, period)

    story = [
        Paragraph("Attempted Exfiltration — Egress Audit", h1),
        Paragraph(f"Reporting period: <b>{period_label}</b>", body),
        Paragraph(f"Generated: <b>{now.strftime('%d %B %Y, %H:%M:%S UTC')}</b>",
                  body),
        Spacer(1, 6 * mm),
    ]

    # --- Summary ---
    unique_dsts = sorted({e["dst"].split(":")[0] for e in events})
    dst_counts = Counter(e["dst"] for e in events)
    summary_rows = [
        ["Metric", "Value"],
        ["Blocked egress attempts", str(len(events))],
        ["Unique destinations", str(len(unique_dsts))],
        ["Bytes exfiltrated", "0 (all attempts dropped at kernel gate)"],
        ["Enforcement point", "eBPF TCX egress hook (default-deny)"],
    ]
    summary = Table(summary_rows, colWidths=[60 * mm, 100 * mm], hAlign="LEFT")
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [summary, Spacer(1, 5 * mm)]

    # --- Detail table ---
    story.append(Paragraph("Blocked egress attempts", styles["Heading2"]))
    if events:
        rows = [["Time (UTC)", "Source host", "Destination", "Proto", "Reason"]]
        for e in sorted(events, key=lambda x: x["dt"], reverse=True):
            rows.append([
                e["dt"].strftime("%d %b %H:%M:%S"),
                e["src"],
                e["dst"],
                e["proto"],
                e["reason"],
            ])
        detail = Table(rows,
                       colWidths=[30 * mm, 38 * mm, 42 * mm, 16 * mm, 34 * mm],
                       hAlign="LEFT")
        detail.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#8a2018")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("TEXTCOLOR", (2, 1), (2, -1), colors.HexColor("#8a2018")),
        ]))
        story += [detail, Spacer(1, 4 * mm)]
    else:
        story += [
            Paragraph("No blocked egress attempts recorded in this period.",
                      body),
            Spacer(1, 4 * mm),
        ]

    # --- Framing / interpretation ---
    story += [
        Paragraph("Interpretation", styles["Heading2"]),
        Paragraph(
            "Each entry is a network flow that attempted to leave the protected "
            "workload to a destination that is not on the sanctioned egress "
            "allowlist and was never cleared by content inspection. Under the "
            "default-deny egress posture, such flows are dropped at the eBPF "
            "kernel hook before any payload leaves the host. The recorded flows "
            "moved zero bytes to their destinations. This audit reflects "
            "flow-level metadata only; the content of blocked flows is not "
            "inspected, because the transfer is denied before content handling.",
            body),
        Spacer(1, 3 * mm),
        Paragraph(
            "Repeated attempts to a single external destination may indicate an "
            "automated exfiltration or command-and-control beacon and warrant "
            "review by the security officer.",
            body),
    ]

    doc = SimpleDocTemplate(path, pagesize=A4,
                            topMargin=20 * mm, bottomMargin=20 * mm,
                            leftMargin=20 * mm, rightMargin=20 * mm,
                            title=f"Sentry ASEAN Exfiltration Audit ({period})")
    doc.build(story, onFirstPage=_watermark, onLaterPages=_watermark)
    print(path)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--period", choices=list(_PERIODS.keys()), default="week")
    ap.add_argument("--log", default=DEFAULT_LOG)
    args = ap.parse_args()
    generate(period=args.period, logpath=args.log)
