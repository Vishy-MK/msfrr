import base64
import binascii
import codecs
import re
from typing import List, Tuple

class PayloadDecoder:
    def __init__(self, max_depth: int = 5):
        self.max_depth = max_depth

    def decode_recursive(self, text: str, current_depth: int = 0) -> List[Tuple[str, str]]:
        """
        Recursively attempt to decode the text using various methods.
        Returns a list of (decoding_type, decoded_text).
        """
        if current_depth >= self.max_depth or not text:
            return []

        results = []
        
        # 1. Base64 Extraction
        # Look for potential base64 strings (length > 8, valid b64 chars)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{8,}=*', text)
        
        # Try individual decodes
        for potential_b64 in b64_matches:
            self._try_b64_decode(potential_b64, results, current_depth)

        # Try a combined decode of all matches joined (detects L7 split base64)
        if len(b64_matches) > 1:
            combined_b64 = "".join(b64_matches)
            self._try_b64_decode(combined_b64, results, current_depth)

        # 2. ROT13 (Try recursively as it might hide another layer)
        try:
            decoded = codecs.encode(text, 'rot_13')
            if decoded != text:
                results.append(("rot13", decoded))
                results.extend(self.decode_recursive(decoded, current_depth + 1))
        except Exception:
            pass

        # 3. URL Encoding
        if '%' in text:
            try:
                import urllib.parse
                decoded = urllib.parse.unquote(text)
                if decoded != text:
                    results.append(("url", decoded))
                    results.extend(self.decode_recursive(decoded, current_depth + 1))
            except Exception:
                pass

        return list(set(results))

    def flatten_payloads(self, text: str) -> List[str]:
        """
        Extract all possible decoded versions of the content.
        """
        decodings = self.decode_recursive(text)
        return [text] + [d[1] for d in decodings]

    def _try_b64_decode(self, b64_str: str, results: list, depth: int):
        try:
            # Add padding if missing
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(b64_str, validate=False).decode('utf-8', errors='ignore')
            if len(decoded) > 5 and any(c.isalnum() for c in decoded):
                results.append(("base64", decoded))
                results.extend(self.decode_recursive(decoded, depth + 1))
        except Exception:
            pass
