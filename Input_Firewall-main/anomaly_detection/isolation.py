"""
isolation.py
------------
Loads the pre-trained Isolation Forest model and scores
incoming feature vectors.

Isolation Forest works by:
  - Randomly partitioning feature space into trees
  - Anomalies are isolated closer to the root (fewer splits needed)
  - score_samples() returns negative anomaly score
  - We map this to 0–30 range

Model must be trained first via: python train_isolation_forest.py
"""

import os
import pickle
import numpy as np

MODEL_PATH = os.getenv("ISO_MODEL_PATH", "models/isolation_forest.pkl")

# Cached model — loaded once on first call
_model = None


def load_model():
    """Load the Isolation Forest from disk. Cached after first load."""
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Isolation Forest model not found at {MODEL_PATH}. "
                "Run: python train_isolation_forest.py"
            )
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model


def compute_iso_score(feature_vector: list[float]) -> tuple[int, str]:
    """
    Score a feature vector using the Isolation Forest.
    Returns (iso_score 0–30, reason_string).

    score_samples() returns values in range roughly (-0.5, 0).
    More negative = more anomalous.
    We normalize to 0–30.
    """
    try:
        model = load_model()
    except FileNotFoundError:
        # Graceful degradation: if model not found, return 0
        return 0, "model_not_loaded"

    X = np.array(feature_vector).reshape(1, -1)
    raw_score = model.score_samples(X)[0]  # typically in [-0.7, -0.1]

    # Normalize: score_samples near -0.5 is normal, near -0.7+ is anomalous
    # Clamp raw_score to [-0.7, -0.1] then invert and scale to 0–30
    normalized = (raw_score - (-0.1)) / ((-0.7) - (-0.1))  # 0 = normal, 1 = anomalous
    normalized = max(0.0, min(1.0, normalized))
    iso_score = int(normalized * 30)

    reason = "isolation_forest_outlier" if iso_score > 15 else "isolation_forest_normal"
    return iso_score, reason
