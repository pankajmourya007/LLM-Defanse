import os
import re
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configs
PII_POLICY = os.getenv("PII_POLICY", "redact").lower()  # "redact" or "block"
ACTIVE_ENTITIES_STR = os.getenv("PII_ENTITIES", "EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,US_SSN,IP_ADDRESS,SECRET_KEY")
ACTIVE_ENTITIES = [e.strip() for e in ACTIVE_ENTITIES_STR.split(",") if e.strip()]

# Presidio is optional — only enable if the env var is set AND the spaCy model is pre-installed.
# This avoids a 400MB auto-download that blocks startup on slow/offline connections.
presidio_analyzer = None
USE_PRESIDIO = os.getenv("USE_PRESIDIO", "false").lower() == "true"
if USE_PRESIDIO:
    try:
        import spacy
        # Check if the model is already installed before importing Presidio
        spacy.load("en_core_web_lg")
        from presidio_analyzer import AnalyzerEngine
        presidio_analyzer = AnalyzerEngine()
        logger.info("Presidio AnalyzerEngine initialized successfully with en_core_web_lg.")
    except Exception as e:
        logger.warning(f"Presidio init skipped ({e}). Using regex PII scanner.")
        presidio_analyzer = None
else:
    logger.info("Presidio disabled (USE_PRESIDIO != true). Using high-performance regex PII scanner.")

# Regex patterns for fallback/offline scanning
REGEX_PATTERNS = {
    "EMAIL_ADDRESS": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
    "PHONE_NUMBER": r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}(?!\d)",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,19}\b",
    "US_SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "IP_ADDRESS": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "SECRET_KEY": r"\b(?:sk-[a-zA-Z0-9]{48}|xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}|[A-Z0-9]{20}\b.*[A-Za-z0-9+/]{40})\b"
}

def check_luhn(card_number: str) -> bool:
    """Validate digits using Luhn algorithm to prevent false positive credit card detections."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        double = d * 2
        total += double if double < 10 else double - 9
    return total % 10 == 0

class PIIScanner:
    @staticmethod
    def scan_regex(text: str) -> list[dict]:
        violations = []
        for entity, pattern in REGEX_PATTERNS.items():
            if entity not in ACTIVE_ENTITIES:
                continue
            for match in re.finditer(pattern, text):
                matched_text = match.group(0)
                
                # Apply Luhn check if it's a CREDIT_CARD
                if entity == "CREDIT_CARD" and not check_luhn(matched_text):
                    continue
                
                violations.append({
                    "entity_type": entity,
                    "text": matched_text,
                    "start": match.start(),
                    "end": match.end(),
                    "score": 1.0  # Heuristics are certain
                })
        return violations

    @staticmethod
    def scan_presidio(text: str) -> list[dict]:
        if not presidio_analyzer:
            return []
        
        # Map Presidio standard entities to our active entities list
        presidio_mapping = {
            "EMAIL_ADDRESS": "EMAIL_ADDRESS",
            "PHONE_NUMBER": "PHONE_NUMBER",
            "CREDIT_CARD": "CREDIT_CARD",
            "US_SSN": "US_SSN",
            "IP_ADDRESS": "IP_ADDRESS",
            "CRYPTO": "SECRET_KEY",  # Map others
        }
        
        results = presidio_analyzer.analyze(text=text, language="en")
        violations = []
        for res in results:
            mapped_type = presidio_mapping.get(res.entity_type, None)
            # If not in custom map, use the original presidio type
            entity_name = mapped_type or res.entity_type
            
            if entity_name in ACTIVE_ENTITIES:
                matched_text = text[res.start:res.end]
                
                # Luhn check validation for credit cards detected by Presidio
                if entity_name == "CREDIT_CARD" and not check_luhn(matched_text):
                    continue
                
                violations.append({
                    "entity_type": entity_name,
                    "text": matched_text,
                    "start": res.start,
                    "end": res.end,
                    "score": res.score
                })
        return violations

    @classmethod
    def scan(cls, text: str) -> list[dict]:
        # Always run regex first (fast, reliable)
        violations = cls.scan_regex(text)
        
        # If Presidio is available, run it to get additional NLP-based entities
        if presidio_analyzer:
            try:
                presidio_violations = cls.scan_presidio(text)
                
                # Merge violations, avoiding duplicates by start/end index overlap
                seen_ranges = {(v["start"], v["end"]) for v in violations}
                for pv in presidio_violations:
                    overlap = False
                    for start, end in seen_ranges:
                        # Check overlap: if start indexes cross
                        if not (pv["end"] <= start or pv["start"] >= end):
                            overlap = True
                            break
                    if not overlap:
                        violations.append(pv)
                        seen_ranges.add((pv["start"], pv["end"]))
            except Exception as e:
                logger.error(f"Presidio scanning error: {e}. Falling back purely to regex.")
        
        # Sort violations by start position descending to facilitate text replacement
        violations.sort(key=lambda x: x["start"], reverse=True)
        return violations

    @classmethod
    def scan_and_redact(cls, prompt: str) -> tuple[str, bool, list[dict]]:
        """
        Scans a prompt for PII.
        Returns:
            redacted_prompt: str
            pii_detected: bool
            violations: list of dict
        """
        if not prompt:
            return prompt, False, []

        violations = cls.scan(prompt)
        pii_detected = len(violations) > 0
        
        # Build redacted prompt (replacing in reverse order so indexes stay valid)
        redacted_prompt = prompt
        for v in violations:
            placeholder = f"<{v['entity_type']}>"
            redacted_prompt = redacted_prompt[:v['start']] + placeholder + redacted_prompt[v['end']:]
            
        # Re-sort violations for logging / API response (ascending order)
        violations.sort(key=lambda x: x["start"])
        return redacted_prompt, pii_detected, violations
