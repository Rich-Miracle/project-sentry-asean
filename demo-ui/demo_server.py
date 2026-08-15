#!/usr/bin/env python3
"""
Project Sentry ASEAN — demo console backend.

Runs inside the sentry container (which shares workload's network namespace),
so outbound sends originate from workload's netns and traverse the transparent
iptables redirect into mitmproxy. The browser only drives the UI; the actual
SMTPS / HTTPS traffic is generated here and is genuinely enforced.

Serves a single-page UI on :8090 and exposes two actions:
  POST /api/email  -> sends an SMTPS message to the mail server
  POST /api/upload -> POSTs a file to the US endpoint over HTTPS
Both return the enforcement outcome (blocked or delivered) plus, where
available, the agent's verdict detail read back from the mitmproxy log.
"""

import base64
import re
import smtplib
import ssl
import time
import threading
import os
from email.message import EmailMessage

import requests
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

MAILSERVER = "172.30.0.10"
US_UPLOAD = "https://172.30.0.22:8443/upload"
SMTP_LOG = "/var/log/sentry/mitm-smtp.log"
HTTPS_LOG = "/var/log/sentry/mitm-https.log"

# Recipient domain -> jurisdiction label, mirrors the addon logic.
RECIP = {
    "us-server": "US (non-equivalent)",
    "my-server": "MY (non-equivalent)",
    "sg-server": "SG (domestic)",
}

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def _linecount(logfile):
    try:
        with open(logfile) as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _verdict_since(logfile, since_line):
    """Parse the verdict from lines added to logfile after `since_line`.
    Handles both SMTP (has clause=) and HTTPS (no clause=) formats."""
    try:
        with open(logfile) as f:
            lines = f.readlines()[since_line:]
    except OSError:
        return None
    for line in reversed(lines):
        m = re.search(r"verdict=(\w+).*?types=\[([^\]]*)\](?:.*?clause=([\w\-]+))?", line)
        if m:
            types = [t.strip().strip("'\"") for t in m.group(2).split(",") if t.strip()]
            return {"verdict": m.group(1), "pii_types": types, "clause": m.group(3)}
    return None


@app.post("/api/email")
def send_email():
    data = request.get_json(force=True)
    to = data.get("to", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")

    domain = to.split("@")[-1] if "@" in to else to
    jurisdiction = next((v for k, v in RECIP.items() if k in domain), "UNKNOWN")

    msg = EmailMessage()
    msg["From"] = "staff@sentry.local"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    _pre = _linecount(SMTP_LOG)
    t0 = time.time()
    error = None

    def _do_send():
        try:
            s = smtplib.SMTP_SSL(MAILSERVER, 465, timeout=30, context=_ctx)
            s.send_message(msg)
            s.quit()
        except Exception:  # noqa: BLE001 — killed flow surfaces here; log is source of truth
            pass

    threading.Thread(target=_do_send, daemon=True).start()

    detail = {}
    for _ in range(150):                      # poll ~30s; breaks the instant the verdict lands
        detail = _verdict_since(SMTP_LOG, _pre) or {}
        if detail:
            break
        time.sleep(0.2)
    blocked = detail.get("verdict") == "BLOCK" if detail else False
    return jsonify({
        "blocked": blocked,
        "jurisdiction": jurisdiction,
        "elapsed": round(time.time() - t0, 1),
        "error": error,
        **detail,
    })


@app.post("/api/upload")
def upload_file():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400
    content = f.read()

    _pre = _linecount(HTTPS_LOG)
    t0 = time.time()
    status = {"v": None}

    def _do_upload():
        try:
            r = requests.post(
                US_UPLOAD,
                files={"file": (f.filename, content)},
                verify=False,
                timeout=30,
            )
            status["v"] = r.status_code
        except Exception as e:  # noqa: BLE001
            status["v"] = type(e).__name__

    threading.Thread(target=_do_upload, daemon=True).start()

    detail = {}
    for _ in range(150):                      # poll ~30s; breaks the instant the verdict lands
        detail = _verdict_since(HTTPS_LOG, _pre) or {}
        if detail:
            break
        time.sleep(0.2)
    blocked = detail.get("verdict") == "BLOCK" if detail else False
    return jsonify({
        "blocked": blocked,
        "status": status["v"],
        "filename": f.filename,
        "jurisdiction": "US (non-equivalent)",
        "elapsed": round(time.time() - t0, 1),
        **detail,
    })


@app.get("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html")) as fh:
        return Response(fh.read(), mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, threaded=True)
