import os
import re
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

THRESHOLD = float(os.getenv("PROMPT_INJECTION_THRESHOLD", "0.5"))

# Weighted heuristics rules
INJECTION_RULES = [
    {
        "id": "direct_override",
        "description": "Direct system instruction overrides",
        "weight": 0.6,
        "patterns": [
            r"\bignore\b.*\b(?:instructions?|rules?|directives?|guidelines?|constraints?)\b",
            r"\bdisregard\b.*\b(?:instructions?|rules?|directives?|guidelines?)\b",
            r"\bforget\b.*\b(?:previous|instructions?|rules?|directives?|guidelines?)\b",
            r"\boverride\b.*\b(?:instructions?|rules?|directives?|guidelines?)\b",
            r"\bnew\b.*\b(?:instructions?|rules?|directives?|guidelines?|role)\b",
        ]
    },
    {
        "id": "system_prompt_leak",
        "description": "System prompt disclosure attempts",
        "weight": 0.5,
        "patterns": [
            r"\b(?:reveal|show|display|print|output|disclosure)\b.*\b(?:system\b.*\bprompt|hidden\b.*\binstructions?)\b",
            r"\bwhat\b.*\b(?:system\b.*\bprompt|initial\b.*\binstructions?)\b",
            r"\b(?:give|list|write)\b.*\b(?:system\b.*\bprompt|instructions?|rules?)\b",
            r"\btext\b.*\babove\b.*\b(?:box|prompt)\b",
        ]
    },
    {
        "id": "roleplay_jailbreak",
        "description": "Jailbreak and roleplay framing",
        "weight": 0.5,
        "patterns": [
            r"\byou\b.*\bare\b.*\bnow\b.*\b(?:dan|developer\s+mode|unrestricted|god\s+mode)\b",
            r"\bdo\s+anything\s+now\b",
            r"\bacting\b.*\bas\b.*\b(?:unrestricted|jailbroken|evil)\b",
            r"\bhypothetical\b.*\bscenario\b.*\b(?:unrestricted|allowed)\b",
            r"\bpretend\b.*\byou\b.*\bhave\b.*\bno\b.*\b(?:rules?|restrictions?|filters?)\b",
        ]
    },
    {
        "id": "exfiltration_markdown",
        "description": "Markdown exfiltration patterns",
        "weight": 0.7,
        "patterns": [
            r"!\[.*?\]\(https?://.*?\?.*?=[a-zA-Z0-9_%+-]+\)",
            r"\[.*?\]\(https?://.*?\?.*?=[a-zA-Z0-9_%+-]+\)",
        ]
    },
    {
        "id": "obfuscation_decoding",
        "description": "Decoding and execution of obfuscated text",
        "weight": 0.4,
        "patterns": [
            r"\b(?:decode|base64|hex|rot13)\b.*\b(?:execute|run|follow|read)\b",
            r"\b(?:parse|eval)\b.*\b(?:base64|string|hex)\b",
        ]
    }
]

class PromptGuard:
    @classmethod
    def analyze(cls, prompt: str) -> tuple[bool, float, list[dict]]:
        """
        Analyzes a prompt for prompt injection attempts.
        Returns:
            injection_detected: bool
            score: float (0.0 to 1.0)
            triggered_rules: list of dict
        """
        if not prompt:
            return False, 0.0, []

        triggered_rules = []
        total_score = 0.0
        prompt_lower = prompt.lower()

        for rule in INJECTION_RULES:
            matched_patterns = []
            for pattern in rule["patterns"]:
                # Use regex search (case insensitive)
                match = re.search(pattern, prompt_lower, re.IGNORECASE)
                if match:
                    matched_patterns.append({
                        "pattern": pattern,
                        "matched_text": match.group(0)
                    })
            
            if matched_patterns:
                # Add to total score, capped at 1.0
                total_score = min(total_score + rule["weight"], 1.0)
                triggered_rules.append({
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "weight": rule["weight"],
                    "matches": matched_patterns
                })

        injection_detected = total_score >= THRESHOLD
        return injection_detected, total_score, triggered_rules
