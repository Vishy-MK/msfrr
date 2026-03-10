"""
train_isolation_forest.py
--------------------------
Trains a small Isolation Forest on synthetic "normal" LLM traffic data
and saves the model to models/isolation_forest.pkl.

Feature space (must match feature_extractor.py → to_vector()):
  [risk_score, prompt_length, token_count, special_char_ratio, entropy, blocked_flag]

Run once before starting the gateway:
  python train_isolation_forest.py
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

# ── Synthetic Training Data ────────────────────────────────────────────────
# Represents "normal" user behavior for a typical LLM API.
# In production you'd replace this with historical baseline traffic logs.

np.random.seed(42)
N_SAMPLES = 2000

def generate_normal_traffic(n: int) -> np.ndarray:
    """
    Generate synthetic normal user traffic.

    Normal users:
      - risk_score: 5–35  (occasional medium-risk queries)
      - prompt_length: 20–500 chars
      - token_count: 5–125 (prompt_length // 4)
      - special_char_ratio: 0.05–0.25
      - entropy: 3.5–5.5 (typical English text)
      - blocked_flag: 0 (normal users rarely get blocked)
    """
    risk_scores   = np.random.uniform(5, 35, n)
    prompt_lens   = np.random.randint(20, 500, n).astype(float)
    token_counts  = (prompt_lens / 4).astype(float)
    sc_ratios     = np.random.uniform(0.05, 0.25, n)
    entropies     = np.random.uniform(3.5, 5.5, n)
    blocked_flags = np.zeros(n)  # Normal traffic → not blocked

    # Stack into feature matrix
    X = np.column_stack([
        risk_scores,
        prompt_lens,
        token_counts,
        sc_ratios,
        entropies,
        blocked_flags,
    ])
    return X


def main():
    print("=" * 50)
    print("  SecureLLM Gateway — Training Isolation Forest")
    print("=" * 50)

    # Generate training data
    X_train = generate_normal_traffic(N_SAMPLES)
    print(f"\n✓ Generated {N_SAMPLES} synthetic normal traffic samples")
    print(f"  Feature shape: {X_train.shape}")
    print(f"  risk_score   — mean: {X_train[:,0].mean():.1f}, std: {X_train[:,0].std():.1f}")
    print(f"  prompt_length— mean: {X_train[:,1].mean():.1f}, std: {X_train[:,1].std():.1f}")
    print(f"  entropy      — mean: {X_train[:,4].mean():.2f}, std: {X_train[:,4].std():.2f}")

    # Train Isolation Forest
    # contamination=0.05 means we expect ~5% of training data could be
    # slightly anomalous (helps calibrate the decision boundary)
    model = IsolationForest(
        n_estimators=50,       # Small — fast inference, good enough for demo
        contamination=0.05,    # Expected fraction of anomalies in training set
        max_features=1.0,      # Use all features for each tree
        bootstrap=False,       # Recommended for Isolation Forest
        random_state=42,
        n_jobs=-1,             # Use all CPU cores
    )

    model.fit(X_train)
    print("\n✓ Isolation Forest trained successfully")

    # Quick sanity check
    test_normal  = np.array([[15.0, 100.0, 25.0, 0.15, 4.5, 0.0]])
    test_anomaly = np.array([[95.0, 2000.0, 500.0, 0.80, 2.0, 1.0]])

    score_normal  = model.score_samples(test_normal)[0]
    score_anomaly = model.score_samples(test_anomaly)[0]

    print(f"\n  Sanity check:")
    print(f"  Normal request score:  {score_normal:.4f}  (closer to 0 = more normal)")
    print(f"  Anomaly request score: {score_anomaly:.4f}  (more negative = more anomalous)")
    assert score_normal > score_anomaly, "Model sanity check failed!"
    print("  ✓ Sanity check passed")

    # Save model
    os.makedirs("models", exist_ok=True)
    model_path = "models/isolation_forest.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    print(f"\n✓ Model saved to: {model_path}")
    print("\nYou can now start the gateway.")
    print("=" * 50)


if __name__ == "__main__":
    main()
