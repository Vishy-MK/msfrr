import re
from typing import List, Dict, Any

class SanitizationEngine:
    def __init__(self):
        # Default sanitization patterns (e.g., stripping suspicious bracketed content)
        self.patterns_to_strip = [
            r"\[.*?\]",  # Strip code-like brackets
            r"\{.*?\}",  # Strip JSON-like curly braces
            r"(?i)(ignore all previous instructions.*?\.)", # Strip common injection starts
            r"[\u200B-\u200D\uFEFF]" # Zero-width characters
        ]

    def sanitize(self, text: str, matches: List[Dict[str, Any]]) -> str:
        """
        Sanitize the prompt based on detected threats.
        """
        sanitized_text = text

        # 1. Apply general strip patterns
        for pattern in self.patterns_to_strip:
            sanitized_text = re.sub(pattern, " [REDACTED] ", sanitized_text)

        # 2. Targeted sanitization based on rules (if specific actions are defined)
        for match in matches:
            if match['action'] == "STRIP":
                # In a more advanced version, we'd use the match's regex to strip
                pass

        # Cleanup extra whitespace resulting from redactions
        sanitized_text = " ".join(sanitized_text.split())
        
        return sanitized_text
