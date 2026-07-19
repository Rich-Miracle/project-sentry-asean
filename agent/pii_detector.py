r"""
Subsystem 4c — Presidio PII Detector for Project Sentry ASEAN.

Detects PII in extracted text. Combines Presidio's built-in recognizers
(EMAIL_ADDRESS, PHONE_NUMBER, PERSON, LOCATION, DATE_TIME, CREDIT_CARD)
with two custom recognizers for Singapore-specific PII:
  - NRIC  : [STFGM]\d{7}[A-Z]      (confidence 0.9)
  - SG_PHONE : (\+65)[689]\d{7}   (confidence 0.85)
"""

import re
from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    EntityRecognizer,
    RecognizerResult
)

# --- OCR-tolerant NRIC recognition -------------------------------------------
# Tesseract reliably confuses characters in the stylized IC typeface:
#   0 <-> O/D/Q,  1 <-> I/l,  5 <-> S,  8 <-> B,  2 <-> Z
# We normalize NRIC-shaped candidates and confirm them with the official
# checksum, so a correction is verified rather than guessed.
_OCR_DIGIT_FIX = str.maketrans({
    "O": "0", "o": "0", "D": "0", "Q": "0",
    "I": "1", "l": "1", "|": "1",
    "S": "5", "B": "8", "Z": "2",
})

# Entities relevant to Singapore PDPA enforcement. Presidio's default registry
# includes US/UK/EU recognizers (US_DRIVER_LICENSE, US_BANK_NUMBER, NHS, etc.)
# that produce false positives on unrelated identifiers and have no bearing on
# the Transfer Limitation Obligation.
_ENTITIES = ["SG_NRIC", "SG_PHONE", "PERSON", "EMAIL_ADDRESS",
             "PHONE_NUMBER", "CREDIT_CARD", "LOCATION", "DATE_TIME", "IBAN_CODE"]

# Loose shape: prefix letter, 7 chars that could be digits or confusables, suffix letter.
_NRIC_LOOSE = re.compile(r"\b([STFGM])([0-9OoDQIlSBZ|]{7})([A-Z])\b")
_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)
_CHECK_ST = "JZIHGFEDCBA"   # for S and T prefixes
_CHECK_FG = "XWUTRQPNMLK"   # for F and G prefixes

def _nric_checksum_valid(nric: str) -> bool:
    """Validate a Singapore NRIC/FIN against its official checksum."""
    if len(nric) != 9:
        return False
    prefix, digits, suffix = nric[0], nric[1:8], nric[8]
    if not digits.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(digits, _WEIGHTS))
    if prefix in ("T", "G"):
        total += 4
    idx = total % 11
    table = _CHECK_ST if prefix in ("S", "T") else _CHECK_FG
    return suffix == table[idx]

class OcrNricRecognizer(EntityRecognizer):
    """Detects NRICs in OCR text, correcting character substitutions and
    confirming each correction with the NRIC checksum."""
    def load(self):
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        for m in _NRIC_LOOSE.finditer(text):
            prefix, middle, suffix = m.groups()
            corrected = prefix + middle.translate(_OCR_DIGIT_FIX) + suffix
            valid = _nric_checksum_valid(corrected)
            was_corrected = corrected != m.group(0)
            # Checksum raises confidence; it does not gate detection. In DLP a
            # false negative (leaked NRIC) is costlier than a false positive,
            # and OCR noise or specimen/test numbers can fail the checksum
            # while still indicating identity data.
            if valid:
                score = 0.85 if was_corrected else 0.95
            else:
                score = 0.55 if was_corrected else 0.65
            results.append(RecognizerResult(
                entity_type="SG_NRIC",
                start=m.start(), end=m.end(), score=score,
            ))
        return results
# -----------------------------------------------------------------------------

def _build_nric_recognizer() -> PatternRecognizer:
    """Singapore NRIC/FIN: prefix letter, 7 digits, suffix letter."""
    pattern = Pattern(
        name="nric_pattern",
        regex=r"[STFGM]\d{7}[A-Z]",
        score=0.9,
    )
    return PatternRecognizer(
        supported_entity="SG_NRIC",
        patterns=[pattern],
        name="NricRecognizer",
    )

def _build_sg_phone_recognizer() -> PatternRecognizer:
    """Singapore mobile: +65 followed by 6/8/9 and 7 digits."""
    pattern = Pattern(
        name="sg_phone_pattern",
        regex=r"(\+65)[689]\d{7}",
        score=0.85,
    )
    return PatternRecognizer(
        supported_entity="SG_PHONE",
        patterns=[pattern],
        name="SgPhoneRecognizer",
    )

class PiiDetector:
    """Wraps Presidio's AnalyzerEngine with Sentry's custom recognizers."""

    def __init__(self):
        self.analyzer = AnalyzerEngine()
        # Register the standard custom recognizers
        self.analyzer.registry.add_recognizer(_build_nric_recognizer())
        self.analyzer.registry.add_recognizer(_build_sg_phone_recognizer())
        # Register the OCR-tolerant NRIC recognizer alongside
        self.analyzer.registry.add_recognizer(OcrNricRecognizer(
            supported_entities=["SG_NRIC"], name="OcrNricRecognizer",
            supported_language="en"
        ))

    def detect(self, text: str, language: str = "en") -> list:
        """
        Analyze text and return a list of detected PII entities.
        Each item: {entity_type, score, start, end, text}.
        """
        results = self.analyzer.analyze(text=text, language=language, entities=_ENTITIES)
        detected = []
        for r in results:
            detected.append({
                "entity_type": r.entity_type,
                "score": round(r.score, 2),
                "start": r.start,
                "end": r.end,
                "text": text[r.start:r.end],
            })
        return detected

# Module-level singleton so the heavy AnalyzerEngine loads once.
_detector = None

def get_detector() -> PiiDetector:
    global _detector
    if _detector is None:
        _detector = PiiDetector()
    return _detector

if __name__ == "__main__":
    # Quick manual smoke test.
    sample = "Customer John Tan, NRIC S8234567A, mobile +6591234567, email john@example.com, and OCR mistake S8234S67A."
    d = get_detector()
    for hit in d.detect(sample):
        print(hit)
