import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

class ViolationLogger:
    def __init__(self):
        # In-memory storage for the internal signal
        self.user_violation_counts = {}
        self.user_critical_counts = {}
        
    def generate_event_id(self, user_id: str, content: str, violation_type: str, mode: str) -> str:
        payload = f"{user_id}:{content}:{violation_type}:{mode}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def get_severity(self, violation_type: str) -> str:
        severity_map = {
            "SECRET_EXPOSURE": "CRITICAL",
            "INTERNAL_SYSTEM_LEAK": "CRITICAL",
            "STRICT_MODE_TRIGGERED": "CRITICAL",
            "HIGH_RISK_OVERRIDE": "CRITICAL",
            "CREDENTIAL_DETECTION": "CRITICAL",
            "SIGNIFICANT_CONTENT_ALTERATION": "CRITICAL",
            "PII_DETECTED": "HIGH",
            "SYSTEM_EXTRACTION_ATTEMPT": "HIGH",
            "INFRASTRUCTURE_LEAK": "HIGH",
            "REGULATORY_VIOLATION": "HIGH",
            "DISALLOWED_ADVICE": "MEDIUM",
            "POLICY_OVERRIDE_ATTEMPT": "MEDIUM",
            "OBFUSCATION_ATTEMPT": "MEDIUM",
            "MINOR_REDACTION": "LOW",
            "TONE_CORRECTION": "LOW"
        }
        return severity_map.get(violation_type, "MEDIUM")

    def log_violation(
        self, 
        user_id: str, 
        original_content: str, 
        sanitized_content: str,
        violation_type: str, 
        mode: str, 
        metadata: Dict[str, Any],
        compliance_profile: List[str],
        boost_severity: bool = False
    ) -> Dict[str, Any]:
        
        event_id = self.generate_event_id(user_id, original_content, violation_type, mode)
        severity = self.get_severity(violation_type)
        if boost_severity:
            severity = "CRITICAL"
        
        # SHA256 fingerprints
        content_fingerprint = hashlib.sha256(original_content.encode()).hexdigest()
        sanitized_fingerprint = hashlib.sha256(sanitized_content.encode()).hexdigest()
        
        event = {
            "event_id": event_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "mode": mode,
            "user_id": user_id,
            "risk_score": metadata.get("risk_score", 0),
            "violation_type": violation_type,
            "policy_profile": metadata.get("org_policy_profile", "DEFAULT"),
            "compliance_context": compliance_profile,
            "severity": severity,
            "blocked": metadata.get("blocked", False),
            "content_fingerprint": content_fingerprint,
            "sanitized_fingerprint": sanitized_fingerprint
        }
        
        # Update escalation flags
        if severity == "CRITICAL":
            self.user_critical_counts[user_id] = self.user_critical_counts.get(user_id, 0) + 1
        
        if severity in ["HIGH", "CRITICAL"]:
            self.user_violation_counts[user_id] = self.user_violation_counts.get(user_id, 0) + 1
            
        return event

    def is_user_escalated(self, user_id: str) -> bool:
        # Top-tier threshold: 3 criticals or 5 high/criticals
        critical_escalated = self.user_critical_counts.get(user_id, 0) >= 3
        general_escalated = self.user_violation_counts.get(user_id, 0) >= 5
        return critical_escalated or general_escalated
