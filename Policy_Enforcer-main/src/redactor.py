import re
import base64
import binascii
import unicodedata
import math
import json
from typing import Tuple, List, Set, Any, Optional

# Enterprise Regex Patterns
PATTERNS = {
    "EMAIL": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
    "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "AADHAAR": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "PASSPORT": r"\b[A-Z][0-9]{7}\b",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "JWT": r"ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "AWS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
    "GROQ_KEY": r"\bgsk_[a-zA-Z0-9_]{48,}\b",
    "API_KEY": r"\b(?:sk|pk|ak|uk|key)_[a-zA-Z0-9_-]{16,}\b",
    "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
    "SWIFT": r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b",
    "HEX_32": r"\b[0-9a-fA-F]{32}\b",
    "HEX_40": r"\b[0-9a-fA-F]{40}\b",
    "HEX_64": r"\b[0-9a-fA-F]{64}\b",
    "MRN": r"\bMRN\s?\d{6,10}\b",
    "PHYSICAL_ADDRESS": r"\d+\s[A-Z][a-z]+\s(Street|St|Avenue|Ave|Road|Rd|Way|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b",
}

# Heuristic Patterns for Names and Indirect Identifiers (GDPR / HIPAA)
GDPR_HEURISTICS = {
    # Detects name after intro: "My name is John Doe"
    "NAME_INTRO": r"(?i)(my name is|i am|this is|patient|user|subject|customer)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
    # Detects name before marker: "John Doe lives at..."
    "NAME_PRE": r"(?i)([A-Z][a-z]+\s+[A-Z][a-z]+)\s+(lives in|lives at|from|located at|address is)",
    # Detects location data
    "LOCATION_DATA": r"(?i)(lives?\bin|lives?\bat|located\bat|from|address\bis)\s+([A-Z][a-z0-9]+(\s+[A-Z][a-z0-9]+)?)",
}

# Context Keywords for Heuristic Detection
CONTEXT_KEYWORDS = [
    "my ssn is", "contact me at", "passport number", "routing number", "my email is",
    "account number", "private key", "secret token", "access key", "api key", "mrn",
    "identification number", "social security", "credit card", "cvv"
]

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not data:
        return 0.0
    entropy = 0
    symbols = {}
    for char in data:
        symbols[char] = symbols.get(char, 0) + 1
    for count in symbols.values():
        p_x = count / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def normalize_obfuscation(content: str) -> str:
    """Enterprise Hardened Normalization Pipeline."""
    content = unicodedata.normalize('NFKC', content)
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u200e', '\u200f']
    for char in zero_width_chars:
        content = content.replace(char, '')
        
    spaced_word_pattern = r"(?:[a-zA-Z]\s){3,}[a-zA-Z]"
    content = re.sub(spaced_word_pattern, lambda m: m.group(0).replace(" ", ""), content)
    
    import urllib.parse
    content = urllib.parse.unquote(content)
    return content

def decode_recursive(content: str, depth: int = 0) -> str:
    if depth >= 2: return content
    original = content
    b64_pattern = r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})?"
    b64_matches = re.findall(b64_pattern, content)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8')
            if all(ord(c) < 128 for c in decoded):
                content = content.replace(match, f"[DECODED_B64: {decode_recursive(decoded, depth + 1)}]")
        except: pass
            
    hex_pattern = r"\b(?:[0-9a-fA-F]{2}){10,}\b"
    hex_matches = re.findall(hex_pattern, content)
    for match in hex_matches:
        try:
            decoded = binascii.unhexlify(match).decode('utf-8')
            if all(ord(c) < 128 for c in decoded):
                content = content.replace(match, f"[DECODED_HEX: {decode_recursive(decoded, depth + 1)}]")
        except: pass
    return content

def scan_structured_json(content: str, whitelist: List[str] = None) -> Tuple[str, List[str]]:
    """Recursive JSON scanning and redaction."""
    if whitelist is None:
        whitelist = []
    
    try:
        data = json.loads(content)
        modifications = []
        
        def recurse(obj: Any) -> Any:
            nonlocal modifications
            if isinstance(obj, str):
                redacted, mods = redact_content(obj, skip_structured=True, whitelist=whitelist)
                modifications.extend(mods)
                return redacted
            elif isinstance(obj, list):
                return [recurse(x) for x in obj]
            elif isinstance(obj, dict):
                return {k: recurse(v) for k, v in obj.items()}
            return obj
            
        redacted_data = recurse(data)
        return json.dumps(redacted_data), list(set(modifications))
    except (json.JSONDecodeError, TypeError):
        return content, []

def mask_credit_card(cc: str) -> str:
    """Masks credit card to show only first 4 and last 4 digits."""
    clean_cc = re.sub(r"[ -]", "", cc)
    if len(clean_cc) < 13: return "[REDACTED_CREDIT_CARD]"
    return f"{clean_cc[:4]} **** **** {clean_cc[-4:]}"

def is_whitelisted(text: str, whitelist: List[str]) -> bool:
    """Check if text matches any whitelist pattern (literal or regex)."""
    if not whitelist:
        return False
    
    for pattern in whitelist:
        try:
            # Try as exact match first
            if text == pattern:
                return True
            # Try as regex pattern
            if re.search(pattern, text):
                return True
        except re.error:
            # If invalid regex, treat as literal
            if text == pattern:
                return True
    
    return False

def redact_content(content: str, skip_structured: bool = False, whitelist: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    if whitelist is None:
        whitelist = []
    
    modifications = set()
    sanitized = content

    # 1. Structural Scanning (JSON / Markdown / Code Blocks)
    if not skip_structured:
        # Markdown Code Blocks (Backticks)
        if "```" in sanitized:
            code_block_pattern = r"```(?:\w+)?\n?(.*?)\n?```"
            matches = re.finditer(code_block_pattern, sanitized, re.DOTALL)
            for match in matches:
                code_text = match.group(1)
                redacted_code, mods = redact_content(code_text, skip_structured=True, whitelist=whitelist)
                if redacted_code != code_text:
                    sanitized = sanitized.replace(code_text, redacted_code)
                    modifications.update(mods)

        # JSON Detection (More aggressive)
        candidate_json = sanitized.strip()
        if candidate_json.startswith('{') or candidate_json.startswith('['):
            redacted_json, mods = scan_structured_json(candidate_json, whitelist=whitelist)
            if redacted_json != candidate_json:
                sanitized = redacted_json
                modifications.update(mods)

    # 2. Priority Secrets (Pre-normalization)
    profile_secrets = ["JWT", "AWS_KEY", "GROQ_KEY", "API_KEY", "HEX_32", "HEX_40", "HEX_64", "IBAN", "SWIFT", "MRN"]
    for secret_type in profile_secrets:
        pattern = PATTERNS[secret_type]
        matches = re.finditer(pattern, sanitized)
        for match in matches:
            found_secret = match.group(0)
            # Skip redaction if whitelisted
            if is_whitelisted(found_secret, whitelist):
                continue
            sanitized = sanitized.replace(found_secret, f"[REDACTED_{secret_type}]", 1)
            modifications.add("SECRET_REDACTED")

    # 3. Normalization & Decoding
    normalized = normalize_obfuscation(sanitized)
    if normalized != sanitized:
        modifications.add("CONTENT_NORMALIZED")
    decoded = decode_recursive(normalized)
    if decoded != normalized:
        modifications.add("OBFUSCATION_DETECTED")
    sanitized = decoded

    # 3.5. Priority Secrets RE-SCAN (Catch nested secrets after decoding)
    for secret_type in profile_secrets:
        pattern = PATTERNS[secret_type]
        matches = re.finditer(pattern, sanitized)
        for match in matches:
            found_secret = match.group(0)
            # Skip redaction if whitelisted
            if is_whitelisted(found_secret, whitelist):
                continue
            sanitized = sanitized.replace(found_secret, f"[REDACTED_{secret_type}]", 1)
            modifications.add("SECRET_REDACTED")

    # 4. Entropy-based Scanning (Strict Tier)
    tokens = re.findall(r"\b[A-Za-z0-9+/=_]{16,}\b", sanitized)
    for token in tokens:
        # Skip redaction if whitelisted
        if is_whitelisted(token, whitelist):
            continue
        entropy = calculate_entropy(token)
        is_hex = all(c in "0123456789abcdefABCDEF" for c in token)
        # Thresholds: Base64 usually > 4.5, Hex usually > 3.0
        if (is_hex and len(token) >= 32 and entropy > 3.0) or (len(token) >= 20 and entropy > 3.8):
            sanitized = sanitized.replace(token, "[REDACTED_SECRET_HIGH_ENTROPY]", 1)
            modifications.add("SECRET_REDACTED")

    # 5. GDPR / HIPAA HEURISTICS (Names / Locations / Identifiers)
    for type_name, pattern in GDPR_HEURISTICS.items():
        matches = re.finditer(pattern, sanitized)
        for match in matches:
            # We want to redact the actual entity group
            if type_name == "NAME_INTRO":
                entity = match.group(2)
            elif type_name == "NAME_PRE":
                entity = match.group(1)
            else: # LOCATION_DATA
                entity = match.group(2)
            
            # Skip redaction if whitelisted
            if is_whitelisted(entity, whitelist):
                continue
            
            sanitized = sanitized.replace(entity, f"[REDACTED_{type_name}]", 1)
            modifications.add("COMPLIANCE_ENFORCED_GDPR")

    # 6. Context-Aware PII
    for kw in CONTEXT_KEYWORDS:
        if kw in sanitized.lower():
            pos = sanitized.lower().find(kw)
            snippet = sanitized[pos:pos+150]
            numeric_match = re.search(r"\b\d{6,16}\b", snippet)
            if numeric_match:
                # If it matches CREDIT_CARD pattern, we use partial masking
                found_num = numeric_match.group(0)
                
                # Skip redaction if whitelisted
                if is_whitelisted(found_num, whitelist):
                    continue
                
                if re.fullmatch(PATTERNS["CREDIT_CARD"], found_num):
                    sanitized = sanitized.replace(found_num, mask_credit_card(found_num), 1)
                else:
                    sanitized = sanitized.replace(found_num, "[REDACTED_CONTEXT_PII]", 1)
                modifications.add("PII_REDACTED")

    # 7. Remaining Patterns
    for type_name, pattern in PATTERNS.items():
        if type_name in profile_secrets: continue
        if type_name == "CREDIT_CARD":
            cc_matches = re.findall(pattern, sanitized)
            for cc in cc_matches:
                # Skip redaction if whitelisted
                if is_whitelisted(cc, whitelist):
                    continue
                sanitized = sanitized.replace(cc, mask_credit_card(cc), 1)
                modifications.add("PII_REDACTED")
            continue
            
        matches = re.findall(pattern, sanitized)
        if matches:
            for match in matches:
                # Skip redaction if whitelisted
                if is_whitelisted(match, whitelist):
                    continue
                sanitized = sanitized.replace(match, f"[REDACTED_{type_name}]", 1)
                modifications.add("PII_REDACTED" if "HEX" not in type_name else "SECRET_REDACTED")
            
    return sanitized, list(modifications)
