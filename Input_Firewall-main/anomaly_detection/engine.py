"""
engine.py
---------
The Anomaly Detection Engine.

Orchestrates the full pipeline:
  1. Extract features from prompt
  2. Update + query Redis baseline
  3. Compute stat_score (Z-score deviation)
  4. Compute iso_score (Isolation Forest)
  5. Compute escalation_score (session trend)
  6. Combine into final anomaly_score (0–100)
  7. Assign status label

This is the single entry point called by the FastAPI handler.
"""

#import redis
from feature_extractor import extract, to_vector, Features
from baseline import update_baseline, get_baseline, compute_stat_score
from isolation import compute_iso_score
from session import push_risk_score, get_history, compute_escalation_score


# Status thresholds
STATUS_MONITOR  = 25   # anomaly_score ≥ 25 → monitor
STATUS_FLAGGED  = 55   # anomaly_score ≥ 55 → flagged
STATUS_BLOCKED  = 80   # anomaly_score ≥ 80 → blocked

RISK_BLOCK_THRESHOLD = 60.0  # risk_score above this → hard block


def _determine_status(anomaly_score: int, hard_blocked: bool) -> str:
    if hard_blocked or anomaly_score >= STATUS_BLOCKED:
        return "blocked"
    if anomaly_score >= STATUS_FLAGGED:
        return "flagged"
    if anomaly_score >= STATUS_MONITOR:
        return "monitor"
    return "normal"


def _mock_model_response(prompt: str, blocked: bool) -> str:
    """Mock LLM response — in production, calls your actual LLM."""
    if blocked:
        return "[BLOCKED] This request was blocked by the security gateway."
    return f"[MOCK LLM] Here is a safe response to your query about: '{prompt[:60]}...'"


def _build_reason(stat_reason: str, iso_reason: str, esc_reason: str,
                  stat_score: int, iso_score: int, esc_score: int) -> str:
    """Pick the dominant reason to surface in the breakdown."""
    scores = {
        stat_reason: stat_score,
        iso_reason: iso_score,
        esc_reason: esc_score,
    }
    dominant = max(scores, key=scores.get)
    # Clean up reason labels
    label_map = {
        "risk_spike": "risk spike",
        "risk_spike + token_spike": "risk spike",
        "token_spike": "token spike",
        "within_baseline": "within baseline",
        "insufficient_baseline": "building baseline",
        "isolation_forest_outlier": "isolation forest outlier",
        "isolation_forest_normal": "no isolation anomaly",
        "model_not_loaded": "no isolation anomaly",
        "session_escalation": "session escalation",
        "session_escalation + session_spike": "session escalation",
        "session_spike": "session escalation",
        "gradual_escalation": "session escalation",
        "no_escalation": "no escalation",
        "insufficient_session_data": "no escalation",
    }
    return label_map.get(dominant, dominant)


def run_anomaly_pipeline(
    user_id: str,
    prompt: str,
    r,
) -> dict:
    """
    Full anomaly detection pipeline.

    Args:
        user_id: Unique identifier for the user/session
        prompt:  Raw prompt string from client
        r:       Redis connection

    Returns:
        Complete gateway response dict.
    """

    # ── Step 1: Feature Extraction ─────────────────────────────────────────
    features: Features = extract(prompt, risk_threshold=RISK_BLOCK_THRESHOLD)
    feature_vec = to_vector(features)
    hard_blocked = features.blocked_flag == 1

    # ── Step 2: Update Redis Baseline ──────────────────────────────────────
    update_baseline(
        r, user_id,
        risk_score=features.risk_score,
        token_count=features.token_count,
        blocked=features.blocked_flag,
    )
    baseline = get_baseline(r, user_id)

    # ── Step 3: Statistical Z-Score Anomaly ────────────────────────────────
    stat_score, stat_reason = compute_stat_score(
        baseline, features.risk_score, features.token_count
    )

    # ── Step 4: Isolation Forest Anomaly ───────────────────────────────────
    iso_score, iso_reason = compute_iso_score(feature_vec)

    # ── Step 5: Session Escalation ─────────────────────────────────────────
    push_risk_score(r, user_id, features.risk_score)
    history = get_history(r, user_id)
    escalation_score, esc_reason = compute_escalation_score(history)

    # ── Step 6: Final Score ────────────────────────────────────────────────
    raw_anomaly = stat_score + iso_score + escalation_score
    anomaly_score = min(100, raw_anomaly)  # Clamp to 100

    # ── Step 7: Status + Response ──────────────────────────────────────────
    status = _determine_status(anomaly_score, hard_blocked)
    response_text = _mock_model_response(prompt, blocked=status == "blocked")

    dominant_reason = _build_reason(
        stat_reason, iso_reason, esc_reason,
        stat_score, iso_score, escalation_score
    )

    return {
        "response": response_text,
        "risk_score": int(features.risk_score),
        "blocked": status == "blocked",
        "anomaly_score": anomaly_score,
        "status": status,
        "anomaly_breakdown": {
            "stat_score": stat_score,
            "iso_score": iso_score,
            "escalation_score": escalation_score,
            "reason": dominant_reason,
        },
        "_debug": {
            "features": {
                "prompt_length": features.prompt_length,
                "token_count": features.token_count,
                "special_char_ratio": features.special_char_ratio,
                "entropy": features.entropy,
                "blocked_flag": features.blocked_flag,
            },
            "baseline": baseline,
            "session_history": history[-5:],  # Last 5 for brevity
        },
    }
