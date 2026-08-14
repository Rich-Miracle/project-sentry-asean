"""
Subsystem 3 — mitmproxy addon for Project Sentry ASEAN.

Intercepts TLS flows, extracts the decrypted body, sends it to the AI agent
for evaluation, and blocks the flow if the verdict is BLOCK.
"""

import base64
import logging

import requests
from mitmproxy import http

logger = logging.getLogger(__name__)

AGENT_URL = "http://localhost:8080/evaluate"

# Static jurisdiction map — mirrors compose/jurisdiction.yaml.
JURISDICTIONS = {
    "172.30.0.20": ("SG", "EQUIVALENT", "none"),
    "172.30.0.21": ("MY", "EQUIVALENT", "ASEAN_MCC"),
    "172.30.0.22": ("US", "NON_EQUIVALENT", "none"),
    "172.30.0.10": ("SG", "EQUIVALENT", "none"),
}


def request(flow: http.HTTPFlow) -> None:
    """Called for every intercepted request, after TLS decryption."""
    body = flow.request.get_content() or b""
    
    # If this is a multipart/form-data upload, extract the uploaded file's raw
    # bytes. Otherwise the router sniffs the multipart envelope (text) instead
    # of the file inside it, and PDF/image extraction never runs.
    ctype = flow.request.headers.get("content-type", "")
    if "multipart/form-data" in ctype and b"boundary=" in ctype.encode():
        boundary = ctype.split("boundary=")[1].strip().encode()
        parts = body.split(b"--" + boundary)
        for part in parts:
            if b"Content-Disposition" in part and b"filename=" in part:
                # File content follows the blank line after the part headers.
                idx = part.find(b"\r\n\r\n")
                if idx != -1:
                    body = part[idx + 4:].rstrip(b"\r\n")
                    break
    if not body:
        return

    dest_ip = flow.server_conn.peername[0] if flow.server_conn.peername else ""
    jurisdiction, classification, safeguard = JURISDICTIONS.get(
        dest_ip, ("UNKNOWN", "NON_EQUIVALENT", "none")
    )

    flow_id = f"{flow.client_conn.peername[0]}->{dest_ip}:{flow.request.port}"
    logger.info("MITM: intercepted %d bytes to %s (%s)",
                len(body), dest_ip, jurisdiction)

    payload = {
        "flow_id": flow_id,
        "dest_ip": dest_ip,
        "dest_port": flow.request.port,
        "jurisdiction": jurisdiction,
        "classification": classification,
	"safeguard": safeguard,
        "content_bytes": base64.b64encode(body).decode(),
        "content_type": flow.request.headers.get("content-type", "text/plain"),
    }

    try:
        r = requests.post(AGENT_URL, json=payload, timeout=60)
        result = r.json()
    except Exception as e:
        logger.warning("MITM: agent call failed: %s", e)
        flow.response = http.Response.make(
            403, b"BLOCKED: Sentry ASEAN (fail-secure)",
            {"Content-Type": "text/plain"}
        )
        return

    verdict = result.get("verdict", "BLOCK")
    logger.info("MITM: verdict=%s pii=%s types=%s",
                verdict, result.get("pii_detected"), result.get("pii_types"))

    if verdict == "BLOCK":
        flow.response = http.Response.make(
            403,
            f"BLOCKED by Project Sentry ASEAN\n"
            f"PDPA clause: {result.get('pdpa_clause')}\n"
            f"PII detected: {result.get('pii_types')}\n".encode(),
            {"Content-Type": "text/plain"},
        )
