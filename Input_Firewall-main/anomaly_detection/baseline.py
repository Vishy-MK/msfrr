"""
baseline.py
-----------
Maintains per-user rolling baselines using in-memory storage.
Uses Exponential Moving Averages (EMA). Fast and requires
no external dependencies like Redis.

State is stored in a module-level dict — resets on server restart.
Swap _store for Redis calls if you need persistence later.
"""

import math

# EMA smoothing factor — higher = faster adaptation to new data
# 0.1 means recent samples get 10% weight; history decays slowly
ALPHA = 0.1

# Minimum requests before baseline is considered reliable
MIN_SAMPLES = 5

# In-memory store: { user_id: { field: value } }
_store: dict = {}


def update_baseline(r, user_id: str,
                    risk_score: float, token_count: int, blocked: int):
    """
    Update the user's EMA baseline with the latest request features.
    Uses Welford-style online variance estimation adapted for EMA.
    r is accepted but unused — kept for API compatibility.
    """
    if user_id not in _store:
        # Bootstrap: first observation becomes the baseline
        _store[user_id] = {
            "avg_risk": risk_score,
            "avg_tokens": float(token_count),
            "avg_blocked": float(blocked),
            "var_risk": 0.0,
            "var_tokens": 0.0,
            "request_count": 1,
        }
    else:
        s = _store[user_id]
        s["request_count"] += 1

        # EMA update for risk
        delta_risk = risk_score - s["avg_risk"]
        s["avg_risk"] += ALPHA * delta_risk
        s["var_risk"] = (1 - ALPHA) * (s["var_risk"] + ALPHA * delta_risk ** 2)

        # EMA update for tokens
        delta_tokens = token_count - s["avg_tokens"]
        s["avg_tokens"] += ALPHA * delta_tokens
        s["var_tokens"] = (1 - ALPHA) * (s["var_tokens"] + ALPHA * delta_tokens ** 2)

        # EMA update for blocked ratio
        s["avg_blocked"] = (1 - ALPHA) * s["avg_blocked"] + ALPHA * blocked

    s = _store[user_id]
    return {
        "avg_risk": s["avg_risk"],
        "avg_tokens": s["avg_tokens"],
        "avg_blocked": s["avg_blocked"],
        "std_risk": math.sqrt(s["var_risk"]),
        "std_tokens": math.sqrt(s["var_tokens"]),
        "request_count": s["request_count"],
    }


def get_baseline(r, user_id: str) -> dict | None:
    """
    Retrieve current baseline for a user.
    Returns None if not enough data yet.
    r is accepted but unused — kept for API compatibility.
    """
    if user_id not in _store or _store[user_id]["request_count"] < MIN_SAMPLES:
        return None  # Not enough history yet

    s = _store[user_id]
    return {
        "avg_risk": s["avg_risk"],
        "avg_tokens": s["avg_tokens"],
        "avg_blocked": s["avg_blocked"],
        "std_risk": math.sqrt(s["var_risk"]),
        "std_tokens": math.sqrt(s["var_tokens"]),
        "request_count": s["request_count"],
    }


def compute_stat_score(baseline: dict | None,
                        risk_score: float,
                        token_count: int) -> tuple[int, str]:
    """
    Compute a statistical anomaly score (0–30) based on Z-score deviation.
    Returns (score, reason_string).

    Logic:
      - If no baseline yet → score 0 (not enough data)
      - Compute z-score for risk_score vs baseline
      - Compute z-score for token_count vs baseline
      - Map combined z-score to 0–30 range
    """
    if baseline is None:
        return 0, "insufficient_baseline"

    reasons = []
    max_z = 0.0

    # Z-score for risk
    std_risk = max(baseline["std_risk"], 1.0)  # avoid division by zero
    z_risk = abs(risk_score - baseline["avg_risk"]) / std_risk
    if z_risk > 2.0:
        reasons.append("risk_spike")
    max_z = max(max_z, z_risk)

    # Z-score for tokens
    std_tokens = max(baseline["std_tokens"], 1.0)
    z_tokens = abs(token_count - baseline["avg_tokens"]) / std_tokens
    if z_tokens > 2.0:
        reasons.append("token_spike")
    max_z = max(max_z, z_tokens)

    # Map combined z to 0–30
    # z=0 → 0, z=1 → ~10, z=2 → ~20, z=3+ → 30
    score = min(30, int(max_z * 10))
    reason = " + ".join(reasons) if reasons else "within_baseline"

    return score, reason
