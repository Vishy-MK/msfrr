from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import os
from .core.decision import DecisionEngine
from .core.validation import StructuralValidator

app = FastAPI(
    title="SecureLLM Input Firewall",
    description="Enterprise-grade security layer for LLM prompt protection.",
    version="1.0.0"
)

# Initialize Engine
RULES_PATH = os.path.join(os.path.dirname(__file__), "config", "rules.yaml")
firewall_engine = DecisionEngine(RULES_PATH)
validator = StructuralValidator()

class FirewallRequest(BaseModel):
    prompt: str = Field(..., description="The user input prompt to analyze")
    target_model_config: Optional[Dict[str, Any]] = Field(default=None, description="Optional target model configuration")
    request_id: Optional[str] = Field(default=None, description="Trace ID for auditing")

class FirewallResponse(BaseModel):
    decision: str = Field(..., description="Action to take: ALLOW, BLOCK, or SANITIZE")
    risk_score: float = Field(..., description="Aggregated risk score (0.0 to 1.0)")
    matches: List[Dict[str, Any]] = Field(default_factory=list, description="List of triggered security rules")
    sanitized_prompt: Optional[str] = Field(default=None, description="The prompt after normalization and cleaning")
    message: Optional[str] = Field(default=None, description="Optional security message for explaining blocks")
    ml_class: Optional[str] = Field(default=None, description="The predicted ML class")
    ml_score: Optional[float] = Field(default=None, description="The raw ML risk score")

@app.post("/firewall/apply", response_model=FirewallResponse)
async def apply_firewall(request: FirewallRequest):
    """
    Apply security filters and ML scoring to the input prompt.
    """
    if not validator.validate(request.prompt, request.target_model_config):
        return FirewallResponse(
            decision="BLOCK",
            risk_score=1.0,
            matches=[{"id": "V001", "name": "Structural Validation Failure", "severity": "HIGH", "action": "BLOCK"}],
            sanitized_prompt=None,
            message="Request blocked by structural validation."
        )

    try:
        result = await firewall_engine.analyze(request.prompt)
        return FirewallResponse(
            decision=result["decision"],
            risk_score=result["risk_score"],
            matches=result["matches"],
            sanitized_prompt=result["sanitized_prompt"],
            message=result.get("message"),
            ml_class=result.get("ml_class"),
            ml_score=result.get("ml_score")
        )
    except Exception as e:
        import traceback
        print(f"FIREWALL ERROR: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal firewall processing error: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "engine": "active"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
