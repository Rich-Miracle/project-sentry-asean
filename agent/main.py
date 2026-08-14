"""
Subsystem 4a — FastAPI server for Project Sentry ASEAN.

Exposes the AI agent as an HTTP service the Go controller calls.
Wires together: router (4b) -> PII detector (4c) -> RAG engine (4d).

Endpoints:
  POST /evaluate  - evaluate a reassembled flow, return a verdict
  GET  /health    - liveness probe
"""

import base64
import logging

from report_gen import generate_report
from rag_engine import justification_store

from fastapi import FastAPI
from pydantic import BaseModel

from router import route
from pii_detector import get_detector
from rag_engine import get_engine

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

# --- Subsystem 7: metrics ---
FLOWS_INSPECTED = Counter("sentry_flows_inspected_total",
                          "Flows sent to the AI agent for evaluation",
                          ["jurisdiction", "content_type"])
VERDICTS = Counter("sentry_verdicts_total", "Verdicts issued",
                   ["verdict", "jurisdiction"])
PII_DETECTED = Counter("sentry_pii_detected_total",
                       "PII entities detected", ["pii_type"])
EVAL_LATENCY = Histogram("sentry_eval_latency_seconds",
                         "Time to return an enforcement verdict",
                         buckets=(1, 2, 5, 10, 20, 30, 60, 120))
REPORTS = Counter("sentry_reports_generated_total", "PDF audit reports generated")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Project Sentry ASEAN — AI Agent")

# Load the heavy singletons once at import time.
_detector = get_detector()
_engine = get_engine()


class EvaluateRequest(BaseModel):
    flow_id: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    jurisdiction: str = "UNKNOWN"
    classification: str = "NON_EQUIVALENT"   # EQUIVALENT | NON_EQUIVALENT
    safeguard: str = "none"                  # none | ASEAN_MCC | CBPR | contract
    content_bytes: str = ""                  # base64-encoded payload
    content_type: str = ""
    timestamp: str = ""


def _assess_sensitivity(pii_types: list) -> str:
    """Rough sensitivity heuristic from detected PII types."""
    high = {"SG_NRIC", "CREDIT_CARD", "US_BANK_NUMBER"}
    if any(t in high for t in pii_types):
        return "high"
    if pii_types:
        return "medium"
    return "low"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/evaluate")
def evaluate(req: EvaluateRequest):
    import time
    _t0 = time.time()

    # 1. Decode payload bytes (base64 -> raw).
    try:
        data = base64.b64decode(req.content_bytes) if req.content_bytes else b""
    except Exception as e:
        logger.warning("base64 decode failed: %s", e)
        data = b""

    # 2. Route + extract text (Step 6).
    text, kind = route(data, content_type=req.content_type)

    # 3. If extraction failed -> fallback to jurisdiction-only.
    if not text:
        # No content to inspect; enforce on jurisdiction alone.
        verdict = "ALLOW"   # no inspectable PII: destination alone is not a lawful basis to block"
        return {
            "verdict": verdict,
            "pdpa_clause": "JURISDICTION-" + req.jurisdiction,
            "pii_detected": False,
            "pii_types": [],
            "sensitivity": "unknown",
            "justification": f"Content unreadable ({kind}); no inspectable "
                             f"personal data, transfer not restricted.",
        }

    # 4. Detect PII (Step 5).
    hits = _detector.detect(text)
    pii_types = sorted({h["entity_type"] for h in hits})
    _WEAK = {"DATE_TIME", "LOCATION", "URL", "NRP"}
    pii_detected = any(t not in _WEAK for t in pii_types)
    # Keep the highest score per entity type (for the audit report).
    pii_scores = {}
    for h in hits:
        et = h["entity_type"]
        pii_scores[et] = max(pii_scores.get(et, 0), h["score"])
    sensitivity = _assess_sensitivity(pii_types)

    FLOWS_INSPECTED.labels(jurisdiction=req.jurisdiction,
                           content_type=req.content_type or "unknown").inc()
    for t in pii_types:
        PII_DETECTED.labels(pii_type=t).inc()

    # 5. Reason for a verdict (Step 7).
    if pii_detected:
        def _on_complete(full: dict, _req=req, _types=pii_types, _sens=sensitivity, _scores=pii_scores):
            """Runs in the background thread once the LLM finishes reasoning."""
            if full.get("verdict") != "BLOCK":
                return
            generate_report({
                "event_id": _req.flow_id or "evt",
                "timestamp": _req.timestamp,
                "verdict": full.get("verdict"),
                "source": "workload",
                "dest_ip": _req.dest_ip,
                "jurisdiction": _req.jurisdiction,
                "content_type": _req.content_type,
                "pii_types": _types,
        "pii_scores": _scores,
                "sensitivity": _sens,
                "pdpa_clause": full.get("cited_clause"),
                "justification": full.get("reason"),
            })
            REPORTS.inc()

        result = _engine.evaluate_fast(pii_types, req.jurisdiction,
                                       req.classification, safeguard=req.safeguard, flow_id=req.flow_id,
                                       on_complete=_on_complete)
        verdict = result.get("verdict", "BLOCK")
        clause = result.get("cited_clause") or ("JURISDICTION-" + req.jurisdiction)
        # A documented safeguard is the legal basis for allowing an otherwise
        # non-equivalent transfer — cite that safeguard's clause.
        if verdict == "ALLOW" and req.safeguard and req.safeguard != "none":
            clause = {"ASEAN_MCC": "PDPA-ASEAN-MCC", "CBPR": "PDPA-CERT",
                      "contract": "PDPA-REG10"}.get(req.safeguard, clause)
        justification = result.get("reason", "")
    else:
        # No personal data present. The PDPA Transfer Limitation Obligation
        # governs personal data only, so destination alone is not a lawful
        # basis to block. Content-aware enforcement means no PII -> ALLOW,
        # regardless of jurisdiction.
        verdict = "ALLOW"
        clause = "JURISDICTION-" + req.jurisdiction
        justification = "No personal data detected; transfer not restricted under PDPA s26."

    VERDICTS.labels(verdict=verdict, jurisdiction=req.jurisdiction).inc()
    EVAL_LATENCY.observe(time.time() - _t0)

    return {
        "verdict": verdict,
        "pdpa_clause": clause,
        "pii_detected": pii_detected,
        "pii_types": pii_types,
        "sensitivity": sensitivity,
        "justification": justification,
    }
    
@app.get("/justification/{flow_id}")
def get_justification(flow_id: str):
    """Retrieve the completed async justification for a flow."""
    return justification_store.get(flow_id, {"status": "pending"})

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

