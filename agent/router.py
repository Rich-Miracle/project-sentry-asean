"""
Subsystem 4b — File-Type Router for Project Sentry ASEAN.

Classifies a reassembled payload and converts it to inspectable text.
Routing (per blueprint Subsystem 4b table):
  - text / JSON / SMTP  -> used directly as UTF-8
  - PDF                 -> extract_pdf
  - DOCX                -> extract_docx
  - PNG / JPEG image    -> extract_image_ocr (Tesseract)
  - unsupported / empty -> ("", "fallback") so caller uses jurisdiction-only

Content type can be given explicitly (from the Go controller's content_type
field) or sniffed from magic bytes when unknown.
"""

import logging

from extractors import extract_pdf, extract_docx, extract_image_ocr

logger = logging.getLogger(__name__)


def _sniff_type(data: bytes) -> str:
    """Guess content type from magic bytes when not provided."""
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:2] == b"PK":  # DOCX is a zip; PK is the zip magic
        return "docx"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image"
    if data[:3] == b"\xff\xd8\xff":  # JPEG
        return "image"
    return "text"


def route(data: bytes, content_type: str = "") -> tuple:
    """
    Convert payload bytes to inspectable text.

    Args:
        data: raw reassembled payload bytes.
        content_type: optional hint from the controller
                      (e.g. "text/smtp", "application/pdf", "image/png").

    Returns:
        (text, kind) where:
          text  = extracted/decoded text (str), or "" if extraction failed
          kind  = the resolved type: "text" | "pdf" | "docx" | "image" | "fallback"
    """
    if not data:
        return "", "fallback"

    ct = (content_type or "").lower()

    # Magic bytes take precedence over the declared content type.
    # The declared type is attacker-controlled: a workload exfiltrating a PDF
    # would simply label it text/plain to evade extraction. Content-aware
    # inspection must derive the type from the bytes themselves.
    sniffed = _sniff_type(data)
    if sniffed and sniffed != "text":
        kind = sniffed
        if ct and sniffed not in ct:
            logger.warning("content-type mismatch: declared=%r, sniffed=%r "
                           "— trusting magic bytes", ct, sniffed)
    elif "pdf" in ct:
        kind = "pdf"
    elif "docx" in ct or "officedocument" in ct:
        kind = "docx"
    elif "image" in ct or "png" in ct or "jpeg" in ct or "jpg" in ct:
        kind = "image"
    elif "text" in ct or "json" in ct or "smtp" in ct:
        kind = "text"
    else:
        kind = sniffed or "text"

    # Dispatch to the right handler.
    if kind == "text":
        try:
            return data.decode("utf-8", errors="replace").strip(), "text"
        except Exception as e:
            logger.warning("text decode failed: %s", e)
            return "", "fallback"

    if kind == "pdf":
        text = extract_pdf(data)
        return (text, "pdf") if text else ("", "fallback")

    if kind == "docx":
        text = extract_docx(data)
        return (text, "docx") if text else ("", "fallback")

    if kind == "image":
        text = extract_image_ocr(data)
        return (text, "image") if text else ("", "fallback")

    return "", "fallback"
