"""
Decision-Based Redaction Engine

Deterministic policy enforcement with source-aware validation.
Handles INPUT/OUTPUT modes with whitelist, echo-safe, and authorized tool logic.
"""

import re
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime


class EntityType(Enum):
    """Types of sensitive entities"""
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"
    AADHAAR = "AADHAAR"
    API_KEY = "API_KEY"
    TOKEN = "TOKEN"
    GENERIC_SECRET = "GENERIC_SECRET"
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    JWT = "JWT"
    AWS_KEY = "AWS_KEY"
    PASSPORT = "PASSPORT"
    IBAN = "IBAN"


class RedactionReason(Enum):
    """Reasons for redaction decisions"""
    NOT_WHITELISTED = "not_whitelisted"
    NOT_ECHO_SAFE = "not_echo_safe"
    NOT_AUTHORIZED = "not_authorized"
    SECURITY_POLICY = "security_policy"
    SYSTEM_PROMPT_DETECTED = "system_prompt_detected"
    ORG_POLICY = "org_policy"


class DecisionType(Enum):
    """Decision types"""
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass
class SensitiveEntity:
    """Represents a detected sensitive entity"""
    value: str
    entity_type: EntityType
    start: int
    end: int
    confidence: float = 1.0
    context: str = ""
    
    def __hash__(self):
        return hash(self.value)
    
    def __eq__(self, other):
        if isinstance(other, SensitiveEntity):
            return self.value == other.value
        return False


@dataclass
class RedactionModification:
    """Records a redaction decision"""
    entity_type: str
    original_value: str
    replacement: str
    reason: str
    decision: str  # ALLOW or REDACT
    position: Tuple[int, int]  # (start, end)
    context: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": "REDACTION",
            "entity_type": self.entity_type,
            "original": self.original_value[:50],  # Truncate for logging
            "replacement": self.replacement,
            "reason": self.reason,
            "decision": self.decision
        }


@dataclass
class EnforcementContext:
    """Context for enforcement decisions"""
    mode: str  # INPUT or OUTPUT
    user_id: str
    org_id: str
    risk_score: int
    compliance_profile: List[str] = field(default_factory=list)
    original_user_inputs: List[str] = field(default_factory=list)
    authorized_data: Dict[str, Set[str]] = field(default_factory=dict)
    request_whitelist: List[str] = field(default_factory=list)
    profile_whitelist: List[str] = field(default_factory=list)
    global_whitelist: List[str] = field(default_factory=list)


class SensitiveEntityDetector:
    """Detects sensitive entities in content"""
    
    # Entity patterns
    PATTERNS = {
        EntityType.EMAIL: r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
        EntityType.PHONE: r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        EntityType.CREDIT_CARD: r"\b(?:\d[ -]*?){13,16}\b",
        EntityType.SSN: r"\b\d{3}-\d{2}-\d{4}\b",
        EntityType.AADHAAR: r"\b\d{4}\s\d{4}\s\d{4}\b",
        EntityType.API_KEY: r"\b(?:sk|pk|ak|uk|key)_[a-zA-Z0-9_-]{16,}\b",
        EntityType.TOKEN: r"\bey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        EntityType.AWS_KEY: r"\bAKIA[0-9A-Z]{16}\b",
        EntityType.PASSPORT: r"\b[A-Z][0-9]{7}\b",
        EntityType.IBAN: r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
    }
    
    # System prompt leak patterns
    SYSTEM_PROMPT_PATTERNS = [
        r"(?i)(system prompt|instruction|role|persona|objective):\s*[\"']?([^\"'\n]+)[\"']?",
        r"(?i)(you are|you will|your task|your job):\s*([^\.!?\n]+)",
        r"(?i)(ignore.*instruction|bypass.*filter|override.*policy)",
    ]
    
    def detect(self, content: str) -> List[SensitiveEntity]:
        """Detect all sensitive entities in content"""
        entities = []
        
        # Check for system prompt leaks first
        if self._detect_system_prompt_leak(content):
            # Return special marker for system prompt
            entities.append(SensitiveEntity(
                value=content[:100],
                entity_type=EntityType.SYSTEM_PROMPT_LEAK,
                start=0,
                end=min(100, len(content))
            ))
        
        # Detect other entities
        for entity_type, pattern in self.PATTERNS.items():
            try:
                matches = re.finditer(pattern, content)
                for match in matches:
                    entity = SensitiveEntity(
                        value=match.group(0),
                        entity_type=entity_type,
                        start=match.start(),
                        end=match.end(),
                        context=content[max(0, match.start()-20):match.end()+20]
                    )
                    entities.append(entity)
            except re.error:
                pass
        
        # Remove duplicates, keep highest confidence
        return self._deduplicate_entities(entities)
    
    def _detect_system_prompt_leak(self, content: str) -> bool:
        """Check for system prompt leak attempts"""
        for pattern in self.SYSTEM_PROMPT_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    def _deduplicate_entities(self, entities: List[SensitiveEntity]) -> List[SensitiveEntity]:
        """Remove duplicate entities, keeping highest confidence"""
        seen = {}
        for entity in sorted(entities, key=lambda e: -e.confidence):
            if entity.value not in seen:
                seen[entity.value] = entity
        return list(seen.values())


class WhitelistResolver:
    """Resolves composite whitelist from multiple sources"""
    
    def __init__(self):
        self.compiled_patterns = {}
    
    def resolve_composite_whitelist(
        self,
        request_whitelist: List[str],
        profile_whitelist: List[str],
        global_whitelist: List[str]
    ) -> List[str]:
        """Merge whitelists (order: request > profile > global)"""
        # Deduplicate while preserving request > profile > global priority
        seen = set()
        composite = []
        
        for pattern in request_whitelist + profile_whitelist + global_whitelist:
            if pattern not in seen:
                seen.add(pattern)
                composite.append(pattern)
        
        return composite
    
    def is_whitelisted(self, value: str, composite_whitelist: List[str]) -> bool:
        """Check if value matches any whitelist pattern"""
        if not composite_whitelist:
            return False
        
        for pattern in composite_whitelist:
            # Try exact match first
            if value == pattern:
                return True
            
            # Try regex match
            try:
                if re.search(pattern, value):
                    return True
            except re.error:
                # Invalid regex, fall back to literal
                pass
        
        return False


class DecisionMatrix:
    """Implements deterministic decision logic"""
    
    def __init__(self):
        self.detector = SensitiveEntityDetector()
        self.whitelist_resolver = WhitelistResolver()
    
    def decide_input_mode(
        self,
        content: str,
        context: EnforcementContext,
        entities: List[SensitiveEntity]
    ) -> Tuple[DecisionType, str]:
        """
        INPUT mode decision logic:
        - If risk_score > 90 → BLOCK
        - If system prompt leak detected → BLOCK
        - Otherwise → ALLOW (but still record detections)
        """
        # Check risk score
        if context.risk_score > 90:
            return DecisionType.BLOCK, "risk_score_exceeded"
        
        # Check for system prompt leaks
        for entity in entities:
            if entity.entity_type == EntityType.SYSTEM_PROMPT_LEAK:
                return DecisionType.BLOCK, "system_prompt_leak_detected"
        
        # Allow by default in INPUT mode
        return DecisionType.ALLOW, "input_mode_allow_by_default"
    
    def decide_output_mode(
        self,
        value: str,
        entity: SensitiveEntity,
        context: EnforcementContext
    ) -> Tuple[DecisionType, RedactionReason]:
        """
        OUTPUT mode decision logic for each entity:
        
        1. If system prompt leak → BLOCK
        2. If value in request whitelist → ALLOW
        3. If value matches profile whitelist → ALLOW
        4. If value matches global whitelist → ALLOW
        5. If value in original user inputs → ALLOW (echo-safe)
        6. If value in authorized data → ALLOW
        7. Otherwise → REDACT
        """
        
        # System prompts always blocked
        if entity.entity_type == EntityType.SYSTEM_PROMPT_LEAK:
            return DecisionType.BLOCK, RedactionReason.SYSTEM_PROMPT_DETECTED
        
        # Resolve composite whitelist
        composite = self.whitelist_resolver.resolve_composite_whitelist(
            context.request_whitelist,
            context.profile_whitelist,
            context.global_whitelist
        )
        
        # Check whitelist (highest priority)
        if self.whitelist_resolver.is_whitelisted(value, composite):
            return DecisionType.ALLOW, RedactionReason.NOT_WHITELISTED  # Allowed by whitelist
        
        # Check echo-safe (user provided this value)
        if self._is_echo_safe(value, context.original_user_inputs):
            return DecisionType.ALLOW, RedactionReason.NOT_ECHO_SAFE  # Allowed by echo-safe
        
        # Check authorized tools
        if self._is_authorized(value, entity.entity_type, context.authorized_data):
            return DecisionType.ALLOW, RedactionReason.NOT_AUTHORIZED  # Allowed by authorization
        
        # Default: redact
        return DecisionType.REDACT, RedactionReason.NOT_WHITELISTED
    
    def _is_echo_safe(self, value: str, original_inputs: List[str]) -> bool:
        """Check if value was in original user input"""
        if not original_inputs:
            return False
        
        # Exact match or substring match in any input
        for input_text in original_inputs:
            if value in input_text or input_text in value:
                return True
        
        return False
    
    def _is_authorized(
        self,
        value: str,
        entity_type: EntityType,
        authorized_data: Dict[str, Set[str]]
    ) -> bool:
        """Check if value is in authorized data"""
        if not authorized_data:
            return False
        
        entity_key = entity_type.value
        if entity_key in authorized_data:
            return value in authorized_data[entity_key]
        
        return False


class RedactionFormatter:
    """Formats redacted content based on entity type"""
    
    REDACTION_TEMPLATES = {
        EntityType.EMAIL: "[REDACTED_EMAIL]",
        EntityType.PHONE: "[REDACTED_PHONE]",
        EntityType.CREDIT_CARD: "[REDACTED_CARD]",
        EntityType.SSN: "[REDACTED_SSN]",
        EntityType.AADHAAR: "[REDACTED_AADHAAR]",
        EntityType.API_KEY: "[REDACTED_API_KEY]",
        EntityType.TOKEN: "[REDACTED_TOKEN]",
        EntityType.GENERIC_SECRET: "[REDACTED_SECRET]",
        EntityType.SYSTEM_PROMPT_LEAK: "[SYSTEM_PROMPT_BLOCKED]",
        EntityType.JWT: "[REDACTED_JWT]",
        EntityType.AWS_KEY: "[REDACTED_AWS_KEY]",
        EntityType.PASSPORT: "[REDACTED_PASSPORT]",
        EntityType.IBAN: "[REDACTED_IBAN]",
    }
    
    def get_replacement(self, entity_type: EntityType) -> str:
        """Get redaction template for entity type"""
        return self.REDACTION_TEMPLATES.get(entity_type, "[REDACTED_SECRET]")
    
    def mask_credit_card(self, cc: str) -> str:
        """Mask credit card (show first 4 and last 4)"""
        clean = re.sub(r"[ -]", "", cc)
        if len(clean) < 13:
            return "[REDACTED_CARD]"
        return f"{clean[:4]} **** **** {clean[-4:]}"


class DecisionEnforcer:
    """Main enforcement engine combining all components"""
    
    def __init__(self):
        self.detector = SensitiveEntityDetector()
        self.decision_matrix = DecisionMatrix()
        self.formatter = RedactionFormatter()
    
    def enforce(
        self,
        content: str,
        context: EnforcementContext
    ) -> Tuple[str, bool, List[RedactionModification]]:
        """
        Main enforcement function
        
        Returns:
            (sanitized_content, should_block, modifications)
        """
        modifications = []
        
        # Detect all entities
        entities = self.detector.detect(content)
        
        # INPUT mode logic
        if context.mode == "INPUT":
            decision, reason = self.decision_matrix.decide_input_mode(content, context, entities)
            
            if decision == DecisionType.BLOCK:
                return content, True, modifications
            
            # Record detections in INPUT mode (but don't redact)
            for entity in entities:
                if entity.entity_type != EntityType.SYSTEM_PROMPT_LEAK:
                    modification = RedactionModification(
                        entity_type=entity.entity_type.value,
                        original_value=entity.value,
                        replacement=entity.value,  # Not redacted
                        reason=reason,
                        decision=DecisionType.ALLOW.value,
                        position=(entity.start, entity.end),
                        context=entity.context
                    )
                    modifications.append(modification)
            
            return content, False, modifications
        
        # OUTPUT mode logic
        sanitized = content
        offset = 0
        sorted_entities = sorted(entities, key=lambda e: e.start)
        
        for entity in sorted_entities:
            decision, reason = self.decision_matrix.decide_output_mode(
                entity.value,
                entity,
                context
            )
            
            if decision == DecisionType.BLOCK:
                return content, True, modifications
            
            if decision == DecisionType.REDACT:
                # Get replacement
                replacement = self.formatter.get_replacement(entity.entity_type)
                if entity.entity_type == EntityType.CREDIT_CARD:
                    replacement = self.formatter.mask_credit_card(entity.value)
                
                # Calculate positions with offset
                start = entity.start + offset
                end = entity.end + offset
                
                # Redact
                sanitized = sanitized[:start] + replacement + sanitized[end:]
                offset += len(replacement) - (entity.end - entity.start)
                
                modification = RedactionModification(
                    entity_type=entity.entity_type.value,
                    original_value=entity.value,
                    replacement=replacement,
                    reason=reason.value,
                    decision=DecisionType.REDACT.value,
                    position=(entity.start, entity.end)
                )
            else:
                # ALLOW
                modification = RedactionModification(
                    entity_type=entity.entity_type.value,
                    original_value=entity.value,
                    replacement=entity.value,
                    reason=reason.value,
                    decision=DecisionType.ALLOW.value,
                    position=(entity.start, entity.end)
                )
            
            modifications.append(modification)
        
        return sanitized, False, modifications


# Singleton instance
_enforcer = None

def get_decision_enforcer() -> DecisionEnforcer:
    """Get or create the decision enforcer singleton"""
    global _enforcer
    if _enforcer is None:
        _enforcer = DecisionEnforcer()
    return _enforcer
