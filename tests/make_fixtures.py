"""Generate test fixtures for the Sentry ASEAN conformance suite."""
import os, shutil
from PIL import Image, ImageDraw
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

D = "/tmp/fixtures"
os.makedirs(D, exist_ok=True)
st = getSampleStyleSheet()

# 1. Text with PII
open(f"{D}/text_pii.txt", "w").write(
    "Customer record: Tan Ah Kow, NRIC S8234567A, phone +6591234567, "
    "email tan@example.com")

# 2. Clean JSON — purely technical, no names
open(f"{D}/text_clean.json", "w").write(
    '{"metric":"cpu_pct","value":42,"host":"node-07","window":"5m"}')

# 3. Credit card
open(f"{D}/text_cc.txt", "w").write(
    "Payment token 4532015112830366 exp 11/28 cvv 456")

# 4. Lookalikes — shaped like NRICs but invalid
open(f"{D}/lookalike.txt", "w").write(
    "Refs: S123 ABC1234567X X9999999Z Q1234567B order-S8234567 SKU-77341")

# 5. PDF with PII
SimpleDocTemplate(f"{D}/doc_pii.pdf", pagesize=A4).build([
    Paragraph("CONFIDENTIAL — Customer Export", st["Heading1"]),
    Paragraph("Tan Ah Kow, NRIC S8234567A, +6591234567", st["BodyText"]),
    Paragraph("Lim Wei Ming, NRIC S9123456B, +6598765432", st["BodyText"]),
])

# 6. PDF, clean
SimpleDocTemplate(f"{D}/doc_clean.pdf", pagesize=A4).build([
    Paragraph("Quarterly Infrastructure Report", st["Heading1"]),
    Paragraph("Mean CPU 42 pct. Disk free 88 pct. No incidents.", st["BodyText"]),
])

# 7. Photo with no text — declared out-of-scope case
img = Image.new("RGB", (400, 300), "#7fb2d9")
ImageDraw.Draw(img).ellipse([120, 60, 280, 220], fill="#e8c39e")
img.save(f"{D}/photo_notext.png")

# 8. Real IC specimen
if os.path.exists("/tmp/ic_card.jpg"):
    shutil.copy("/tmp/ic_card.jpg", f"{D}/ic_card.jpg")

for f in sorted(os.listdir(D)):
    print(f"{os.path.getsize(D+'/'+f):>8}  {f}")
