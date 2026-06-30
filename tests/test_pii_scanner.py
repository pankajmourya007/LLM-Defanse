import pytest
from app.services.pii_scanner import PIIScanner

def test_email_detection():
    prompt = "Hi, my contact is john.doe@corp.com, send me details."
    redacted, detected, violations = PIIScanner.scan_and_redact(prompt)
    assert detected is True
    assert "john.doe@corp.com" in [v["text"] for v in violations]
    assert redacted == "Hi, my contact is <EMAIL_ADDRESS>, send me details."

def test_phone_detection():
    prompt = "Call me at +1-555-0199 or 555-123-4567."
    redacted, detected, violations = PIIScanner.scan_and_redact(prompt)
    assert detected is True
    assert redacted == "Call me at <PHONE_NUMBER> or <PHONE_NUMBER>."

def test_credit_card_detection_with_luhn():
    # Invalid credit card (fails Luhn)
    prompt_fail = "Check out card 4111111111111112"
    _, detected_fail, _ = PIIScanner.scan_and_redact(prompt_fail)
    assert detected_fail is False

    # Valid card (passes Luhn, VISA)
    prompt_pass = "Check out card 4111111111111111"
    redacted, detected_pass, violations = PIIScanner.scan_and_redact(prompt_pass)
    assert detected_pass is True
    assert redacted == "Check out card <CREDIT_CARD>"

def test_no_pii():
    prompt = "Tell me a joke about security gateways."
    redacted, detected, violations = PIIScanner.scan_and_redact(prompt)
    assert detected is False
    assert redacted == prompt
    assert len(violations) == 0
