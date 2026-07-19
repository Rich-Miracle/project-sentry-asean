"""
Subsystem 4b — Content Extractors for Project Sentry ASEAN.

Converts reassembled payload bytes into inspectable text, by type:
  - PDF   -> pdfminer.six
  - DOCX  -> python-docx
  - Image -> Tesseract OCR (via pytesseract + Pillow)

Each extractor takes raw bytes and returns extracted text (str).
On failure, returns an empty string so the caller can fall back to
jurisdiction-only enforcement (per blueprint Subsystem 4b fallback row).
"""

import io
import logging

logger = logging.getLogger(__name__)


def extract_pdf(data: bytes) -> str:
    """
    Extract text from PDF bytes.

    Two-stage strategy:
      1. pdfminer.six for text-based PDFs (fast, exact).
      2. If that yields little/no text, the PDF is likely scanned/image-based,
         so render each page to an image and OCR it with Tesseract.
    Returns extracted text, or "" on total failure (caller falls back).
    """
    text = ""
    # --- Stage 1: direct text extraction ---
    try:
        from pdfminer.high_level import extract_text
        text = extract_text(io.BytesIO(data)).strip()
    except Exception as e:
        logger.warning("PDF text extraction failed: %s", e)
        text = ""

    # If we got a reasonable amount of text, we're done.
    if len(text) >= 20:
        return text

    # --- Stage 2: OCR fallback for scanned/image PDFs ---
    logger.info("PDF has little/no text (%d chars); trying OCR fallback", len(text))
    try:
        from pdf2image import convert_from_bytes
        import pytesseract
        pages = convert_from_bytes(data, dpi=200)
        ocr_chunks = []
        for i, page_img in enumerate(pages):
            page_text = pytesseract.image_to_string(page_img)
            if page_text.strip():
                ocr_chunks.append(page_text.strip())
        ocr_text = "\n".join(ocr_chunks).strip()
        if ocr_text:
            logger.info("OCR fallback recovered %d chars from %d page(s)",
                        len(ocr_text), len(pages))
            return ocr_text
    except Exception as e:
        logger.warning("PDF OCR fallback failed: %s", e)

    # Return whatever little text we had (may be ""), caller handles fallback.
    return text


def extract_docx(data: bytes) -> str:
    """Extract text from DOCX bytes using python-docx."""
    try:
        import docx
        document = docx.Document(io.BytesIO(data))
        paragraphs = [p.text for p in document.paragraphs]
        return "\n".join(paragraphs).strip()
    except Exception as e:
        logger.warning("DOCX extraction failed: %s", e)
        return ""


def extract_image_ocr(data: bytes) -> str:
    """Extract text printed in an image using Tesseract OCR."""
    try:
        import pytesseract
        from PIL import Image
        image = Image.open(io.BytesIO(data))
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception as e:
        logger.warning("OCR extraction failed: %s", e)
        return ""
