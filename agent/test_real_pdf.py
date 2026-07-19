"""Run a real PDF through the full chain: extract -> route -> detect."""
import sys
from router import route
from pii_detector import get_detector

pdf_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/real.pdf"

with open(pdf_path, "rb") as f:
    data = f.read()

print(f"Loaded {len(data)} bytes from {pdf_path}\n")

text, kind = route(data, content_type="application/pdf")
print(f"Routed as: {kind}")
print(f"Extracted text ({len(text)} chars):")
print("-" * 50)
print(text)
print("-" * 50)

if not text:
    print("\nNo text extracted -> would fall back to jurisdiction-only.")
    sys.exit(0)

detector = get_detector()
hits = detector.detect(text)
print(f"\nPII detected ({len(hits)} entities):")
for h in hits:
    print(f"  {h['entity_type']:18} score={h['score']:.2f}  text={h['text']!r}")
