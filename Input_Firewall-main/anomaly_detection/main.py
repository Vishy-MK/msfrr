"""
main.py
-------
SecureLLM Gateway — FastAPI entrypoint.

Routes:
  POST /query          → Main gateway endpoint
  GET  /health         → Health check
  GET  /user/{id}/baseline  → Inspect user baseline (debug)
  DELETE /user/{id}/reset   → Reset user state (demo helper)
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from engine import run_anomaly_pipeline

# ── App Setup ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureLLM Gateway",
    description="Anomaly Detection Engine for LLM request monitoring",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── No Redis — using in-memory store ──────────────────────────────────────
# State lives in anomaly/baseline.py (_store) and anomaly/session.py (_sessions)
# Resets on server restart — fine for local demo use
redis_client = None


# ── Request / Response Models ──────────────────────────────────────────────
class QueryRequest(BaseModel):
    user_id: str = Field(..., example="user_42", description="Unique user identifier")
    prompt: str  = Field(..., example="Tell me about machine learning")


class AnomalyBreakdown(BaseModel):
    stat_score: int
    iso_score: int
    escalation_score: int
    reason: str


class QueryResponse(BaseModel):
    response: str
    risk_score: int
    blocked: bool
    anomaly_score: int
    status: str
    anomaly_breakdown: AnomalyBreakdown


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check."""
    return {"status": "ok", "storage": "in-memory"}


@app.post("/query", response_model=QueryResponse)
def query(req: QueryRequest):
    """
    Main gateway endpoint.

    Flow:
      Client prompt → Feature extraction → Baseline check →
      Isolation Forest → Session escalation → Anomaly score → Response
    """
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    result = run_anomaly_pipeline(
        user_id=req.user_id,
        prompt=req.prompt,
        r=redis_client,
    )
    return result


@app.get("/user/{user_id}/baseline")
def get_user_baseline(user_id: str):
    """
    Debug endpoint: inspect stored baseline for a user.
    Useful for demos — shows what the system has learned.
    """
    from baseline import get_baseline
    from session import get_history

    baseline = get_baseline(redis_client, user_id)
    history = get_history(redis_client, user_id)

    return {
        "user_id": user_id,
        "baseline": baseline or "insufficient data (need 5+ requests)",
        "risk_score_history": history,
    }


@app.delete("/user/{user_id}/reset")
def reset_user(user_id: str):
    """
    Demo helper: wipe all in-memory state for a user.
    Lets you restart a demo scenario cleanly.
    """
    from baseline import _store as baseline_store
    from session import _sessions as session_store

    baseline_store.pop(user_id, None)
    session_store.pop(user_id, None)

    return {"message": f"Reset complete for user '{user_id}'"}


@app.get("/")
def root():
    return {
        "service": "SecureLLM Gateway",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": ["/query", "/health", "/user/{id}/baseline", "/user/{id}/reset"],
    }
