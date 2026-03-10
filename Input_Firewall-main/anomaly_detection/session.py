"""
session.py
----------
Tracks the last N risk scores per user in memory and detects
escalation patterns — when a user's requests are trending
toward higher risk over time.

State is stored in a module-level dict — resets on server restart.
Swap _sessions for Redis calls if you need persistence later.

Escalation signals:
  1. Monotonic increase (each score higher than previous)
  2. Linear trend slope above threshold
  3. Sudden jump at end of session window
"""

MAX_WINDOW = 10        # Store last 10 risk scores
SLOPE_THRESHOLD = 3.0  # Risk points per request = escalating

# In-memory store: { user_id: [risk_scores] }
_sessions: dict = {}


def push_risk_score(r, user_id: str, risk_score: float):
    """
    Append the latest risk score to the user's session history.
    Trims the list to MAX_WINDOW entries.
    r is accepted but unused — kept for API compatibility.
    """
    if user_id not in _sessions:
        _sessions[user_id] = []
    _sessions[user_id].append(risk_score)
    # Keep only last MAX_WINDOW entries
    _sessions[user_id] = _sessions[user_id][-MAX_WINDOW:]


def get_history(r, user_id: str) -> list[float]:
    """
    Retrieve the user's risk score history.
    r is accepted but unused — kept for API compatibility.
    """
    return _sessions.get(user_id, [])


def _linear_slope(values: list[float]) -> float:
    """
    Compute slope of a simple linear regression line through the values.
    Positive slope = increasing trend.
    """
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2
    y_mean = sum(values) / n
    numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
    denominator = sum((i - x_mean) ** 2 for i in range(n))
    return numerator / denominator if denominator != 0 else 0.0


def compute_escalation_score(history: list[float]) -> tuple[int, str]:
    """
    Detect escalation in session and return (score 0–40, reason).

    Scoring logic:
      - Need at least 3 samples to detect a trend
      - Compute linear slope across risk history
      - Map slope to escalation score
      - Bonus points for monotonic increase at end of window
    """
    if len(history) < 3:
        return 0, "insufficient_session_data"

    slope = _linear_slope(history)
    reasons = []

    if slope <= 0:
        return 0, "no_escalation"

    # Check if last 3 scores are strictly increasing
    last_3 = history[-3:]
    monotonic = all(last_3[i] < last_3[i + 1] for i in range(len(last_3) - 1))
    if monotonic:
        reasons.append("session_escalation")

    # Check for sudden spike at end vs session average
    session_avg = sum(history[:-1]) / max(1, len(history) - 1)
    last_score = history[-1]
    spike_ratio = (last_score - session_avg) / max(1.0, session_avg)
    if spike_ratio > 0.5:
        reasons.append("session_spike")

    # Map slope to score:
    # slope=0 → 0, slope=SLOPE_THRESHOLD → 20, slope=2x threshold → 40
    slope_score = min(20, int((slope / SLOPE_THRESHOLD) * 20))

    # Monotonic bonus: up to 20 points
    monotonic_bonus = 15 if monotonic else 0
    spike_bonus = 10 if spike_ratio > 0.5 else 0

    escalation_score = min(40, slope_score + monotonic_bonus + spike_bonus)
    reason = " + ".join(reasons) if reasons else "gradual_escalation"

    return escalation_score, reason
