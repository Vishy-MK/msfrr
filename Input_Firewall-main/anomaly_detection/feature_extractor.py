"""
feature_extractor.py
--------------------
Extracts numerical features from each incoming prompt.
These features are used by both the statistical baseline
and the Isolation Forest model.
"""

import math
import string
import random
from dataclasses import dataclass


@dataclass
class Features:
    risk_score: float        # Mocked risk classifier output (0–100)
    prompt_length: int       # Raw character count
    token_count: int         # Approximate token count
    special_char_ratio: float  # Ratio of non-alphanumeric chars
    entropy: float           # Shannon entropy of the prompt
    blocked_flag: int        # 1 if risk_score > threshold, else 0


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _mock_risk_score(prompt: str) -> float:
    """
    Mock risk classifier.
    In production this would call your actual classifier.
    Seeds on prompt content so repeated identical prompts
    return consistent scores (useful for demos).
    """
    # Simple heuristic: suspicious keywords bump the score
    SUSPICIOUS = ["ignore previous", "jailbreak", "bypass", "DAN", "sudo",
                  "hack", "exploit", "injection", "reveal system prompt"]
    base = random.uniform(5, 30)  # normal background noise
    for kw in SUSPICIOUS:
        if kw.lower() in prompt.lower():
            base += random.uniform(25, 45)
    return min(base, 100.0)


def extract(prompt: str, risk_threshold: float = 60.0) -> Features:
    """
    Main entry point. Given a raw prompt string, return a Features object.
    """
    risk_score = _mock_risk_score(prompt)
    prompt_length = len(prompt)
    # Rough token approximation: 1 token ≈ 4 characters
    token_count = max(1, prompt_length // 4)
    special_chars = sum(1 for ch in prompt if ch in string.punctuation or ch in " \t\n")
    special_char_ratio = special_chars / max(1, prompt_length)
    entropy = _shannon_entropy(prompt)
    blocked_flag = 1 if risk_score > risk_threshold else 0

    return Features(
        risk_score=round(risk_score, 2),
        prompt_length=prompt_length,
        token_count=token_count,
        special_char_ratio=round(special_char_ratio, 4),
        entropy=round(entropy, 4),
        blocked_flag=blocked_flag,
    )


def to_vector(f: Features) -> list[float]:
    """Convert Features to a flat list for ML model input."""
    return [
        f.risk_score,
        f.prompt_length,
        f.token_count,
        f.special_char_ratio,
        f.entropy,
        float(f.blocked_flag),
    ]
