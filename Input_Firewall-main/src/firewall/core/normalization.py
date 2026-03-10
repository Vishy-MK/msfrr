import unicodedata
import re

class NormalizationEngine:
    def __init__(self):
        # Pattern to find zero-width characters and other hidden markers
        self.hidden_chars_pattern = re.compile(r"[\u200B-\u200D\uFEFF\u00AD]")
        # Homoglyph Map (Cyrillic to Latin examples)
        self.homoglyph_map = str.maketrans(
            "абсенорукхјіѕТАБСЕНОРУКХЈІЅ", 
            "abcehopukxjisTABCEHOPUKXJIS"
        )

    def normalize(self, text: str) -> str:
        """
        Apply a series of normalization steps to canonicalize the input.
        """
        if not text:
            return ""

        # 1. Strip hidden characters
        text = self.hidden_chars_pattern.sub("", text)

        # 2. Unicode Normalization (NFKC)
        text = unicodedata.normalize("NFKC", text)

        # 3. Canonicalize Homoglyphs
        text = text.translate(self.homoglyph_map)

        # 4. Whitespace Normalization
        text = " ".join(text.split())

        return text

    def strip_adversarial_obfuscation(self, text: str) -> str:
        """
        Aggressive cleanup of common bypass characters like extra spacing, dots, etc.
        """
        # Remove repeated non-alphanumeric characters (e.g., "S.E.C.U.R.E")
        text = re.sub(r'([^\w\s])\s*(?=\1)', '', text)
        return text
