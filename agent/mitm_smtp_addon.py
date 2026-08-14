"""
Subsystem 3 — mitmproxy SMTPS addon for Project Sentry ASEAN.

Intercepts implicit-TLS SMTP (port 465), extracts the decrypted message,
sends it to the AI agent, and kills the flow on a BLOCK verdict.

Note: mitmproxy does not support STARTTLS (opportunistic TLS upgrade), so
this targets implicit TLS per RFC 8314, via --mode reverse:tls://host:465
"""

import base64
import logging
import re

import requests
from mitmproxy import tcp

logger = logging.getLogger(__name__)

AGENT_URL = "http://localhost:8080/evaluate"
END_OF_DATA = b"\r\n.\r\n"

# Recipient domain -> (jurisdiction, classification).
# For email, the destination that matters is the recipient, not the relay.
RECIPIENT_JURISDICTIONS = {
    "us-server": ("US", "NON_EQUIVALENT", "none"),
    "my-server": ("MY", "NON_EQUIVALENT", "ASEAN_MCC"),
    "sg-server": ("SG", "EQUIVALENT", "none"),
}

_buffers = {}
_RCPT_RE = re.compile(rb"RCPT TO:\s*<[^@>]*@([^>]+)>", re.IGNORECASE)


def _resolve_recipient(buf: bytes):
    m = _RCPT_RE.search(buf)
    if not m:
        return "UNKNOWN", "NON_EQUIVALENT", "none", "unknown"
    domain = m.group(1).decode(errors="replace")
    for key, (j, c, s) in RECIPIENT_JURISDICTIONS.items():
        if key in domain:
            return j, c, s, domain
    return "UNKNOWN", "NON_EQUIVALENT", "none", domain


def tcp_message(flow: tcp.TCPFlow):
    msg = flow.messages[-1]
    if not msg.from_client:
        return

    fid = id(flow)
    buf = _buffers.get(fid, b"") + msg.content
    _buffers[fid] = buf

    # Wait for the complete DATA section.
    if END_OF_DATA not in msg.content and END_OF_DATA not in buf:
        return

    held = msg.content
    msg.content = b""

    jurisdiction, classification, safeguard, domain = _resolve_recipient(buf)

    idx = buf.find(b"DATA\r\n")
    body = buf[idx + 6:] if idx != -1 else buf
    body = body.split(END_OF_DATA)[0]

    logger.info("MITM-SMTP: %d bytes to %s (%s)", len(body), domain, jurisdiction)

    payload = {
        "flow_id": f"smtp-{fid}",
        "dest_ip": flow.server_conn.peername[0] if flow.server_conn.peername else "",
        "dest_port": 465,
        "jurisdiction": jurisdiction,
        "classification": classification,
        "safeguard": safeguard,
        "content_bytes": base64.b64encode(body).decode(),
        "content_type": "text/plain",
    }

    try:
        result = requests.post(AGENT_URL, json=payload, timeout=60).json()
    except Exception as e:
        logger.warning("MITM-SMTP: agent call failed, fail-secure: %s", e)
        _buffers.pop(fid, None)
        flow.kill()
        return

    verdict = result.get("verdict", "BLOCK")
    logger.info("MITM-SMTP: verdict=%s pii=%s types=%s clause=%s",
                verdict, result.get("pii_detected"),
                result.get("pii_types"), result.get("pdpa_clause"))

    _buffers.pop(fid, None)

    if verdict == "BLOCK":
        logger.info("MITM-SMTP: BLOCKING — terminator withheld, killing flow")
        flow.kill()          # msg.content stays empty; message never committed
    else:
        # Per-flow safe-flag: tell the controller to clear THIS exact outbound
        # tuple in the kernel map, so eBPF passes it. Must land before release.
        try:
            sn = flow.server_conn.sockname   # (src_ip, src_port)
            pn = flow.server_conn.peername   # (dst_ip, dst_port)
            requests.post("http://127.0.0.1:9095/clear", timeout=3, json={
                "src_ip": sn[0], "src_port": sn[1],
                "dst_ip": pn[0], "dst_port": pn[1],
            })
            logger.info("MITM-SMTP: flow cleared %s:%s -> %s:%s", sn[0], sn[1], pn[0], pn[1])
        except Exception as e:
            logger.warning("MITM-SMTP: clearance write failed: %s", e)
        msg.content = held   # release: Postfix sees \r\n.\r\n and queues it
