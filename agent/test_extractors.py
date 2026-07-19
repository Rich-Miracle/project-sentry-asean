"""
Step 6 verification — generate real PDF/image test files, extract text,
and confirm the embedded PII survives the extraction round-trip.
"""

from router import route
from pii_detector import get_detector


def make_test_pdf(path):
    """Create a PDF containing a fake customer record with an NRIC."""
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(path)
    c.drawString(72, 720, "CONFIDENTIAL CUSTOMER RECORD")
    c.drawString(72, 700, "Name: Tan Ah Kow")
    c.drawString(72, 680, "NRIC: S8234567A")
    c.drawString(72, 660, "Mobile: +6591234567")
    c.save()


def make_test_image(path):
    """Create a PNG that looks like a scanned IC card with printed text."""
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (600, 200), color="white")
    draw = ImageDraw.Draw(img)
    # Default font is fine for OCR; large size helps Tesseract accuracy.
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28)
    except Exception:
        font = ImageFont.load_default()
    draw.text((20, 30),  "REPUBLIC OF SINGAPORE", fill="black", font=font)
    draw.text((20, 80),  "Name: LIM WEI MING",    fill="black", font=font)
    draw.text((20, 130), "NRIC: S1234567D",        fill="black", font=font)
    img.save(path)


def run():
    detector = get_detector()

    # --- PDF round-trip ---
    make_test_pdf("/tmp/test_record.pdf")
    with open("/tmp/test_record.pdf", "rb") as f:
        pdf_bytes = f.read()
    pdf_text, pdf_kind = route(pdf_bytes, content_type="application/pdf")
    print(f"[PDF]   kind={pdf_kind}")
    print(f"[PDF]   extracted text:\n{pdf_text}\n")
    pdf_pii = detector.detect(pdf_text)
    print(f"[PDF]   PII detected: {[h['entity_type'] for h in pdf_pii]}")
    assert pdf_kind == "pdf", "PDF not routed correctly"
    assert "S8234567A" in pdf_text, "NRIC not extracted from PDF"
    assert any(h["entity_type"] == "SG_NRIC" for h in pdf_pii), "NRIC not detected in PDF text"
    print("[PDF]   PASS\n")

    # --- Image OCR round-trip ---
    make_test_image("/tmp/test_ic.png")
    with open("/tmp/test_ic.png", "rb") as f:
        img_bytes = f.read()
    img_text, img_kind = route(img_bytes, content_type="image/png")
    print(f"[IMAGE] kind={img_kind}")
    print(f"[IMAGE] OCR text:\n{img_text}\n")
    img_pii = detector.detect(img_text)
    print(f"[IMAGE] PII detected: {[h['entity_type'] for h in img_pii]}")
    assert img_kind == "image", "Image not routed correctly"
    # OCR is imperfect; check the NRIC survived (allow minor OCR noise).
    assert "S1234567D" in img_text.replace(" ", ""), "NRIC not OCR'd from image"
    print("[IMAGE] PASS\n")

    # --- Plain text passthrough ---
    txt_text, txt_kind = route(b"Plain JSON: {\"nric\": \"T0123456J\"}", content_type="text/plain")
    print(f"[TEXT]  kind={txt_kind}, text={txt_text}")
    assert txt_kind == "text"
    print("[TEXT]  PASS\n")

    print("=== Step 6 extraction verification: ALL PASSED ===")


if __name__ == "__main__":
    run()
