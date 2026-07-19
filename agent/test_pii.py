"""
Unit tests for Subsystem 4c — Presidio PII Detector.
Step 5 completion criteria: NRIC, email, phone detected correctly in isolation.
"""

from pii_detector import get_detector


def _entity_types(results):
    """Helper: extract just the set of detected entity types."""
    return {r["entity_type"] for r in results}


def _find(results, entity_type):
    """Helper: return the first result of a given entity type, or None."""
    for r in results:
        if r["entity_type"] == entity_type:
            return r
    return None


def test_nric_detected():
    d = get_detector()
    results = d.detect("Customer NRIC is S8234567A on file.")
    nric = _find(results, "SG_NRIC")
    assert nric is not None, "NRIC not detected"
    assert nric["text"] == "S8234567A"
    assert nric["score"] >= 0.9


def test_sg_phone_detected():
    d = get_detector()
    results = d.detect("Call me at +6591234567 tomorrow.")
    phone = _find(results, "SG_PHONE")
    assert phone is not None, "SG phone not detected"
    assert phone["text"] == "+6591234567"
    assert phone["score"] >= 0.85


def test_email_detected():
    d = get_detector()
    results = d.detect("Send the report to john.tan@example.com please.")
    email = _find(results, "EMAIL_ADDRESS")
    assert email is not None, "Email not detected"
    assert email["text"] == "john.tan@example.com"


def test_person_detected():
    d = get_detector()
    results = d.detect("The account belongs to John Tan.")
    assert "PERSON" in _entity_types(results), "PERSON not detected"


def test_combined_pii():
    """The blueprint's data-flow example: a customer record with multiple PII."""
    d = get_detector()
    text = "Customer John Tan, NRIC S8234567A, mobile +6591234567, email john@example.com"
    types = _entity_types(d.detect(text))
    assert "SG_NRIC" in types
    assert "SG_PHONE" in types
    assert "EMAIL_ADDRESS" in types
    assert "PERSON" in types


def test_no_pii_clean_text():
    """Text with no PII should produce no high-confidence PII entities."""
    d = get_detector()
    results = d.detect("The weather is nice and the server is running fine.")
    # No NRIC, no phone, no email expected.
    types = _entity_types(results)
    assert "SG_NRIC" not in types
    assert "SG_PHONE" not in types
    assert "EMAIL_ADDRESS" not in types
