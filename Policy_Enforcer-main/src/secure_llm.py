"""
SecureLLM: Enterprise-Grade LLM Wrapper with Dual-Layer Policy & Redaction Enforcement

A stateless wrapper that applies policy enforcement and redaction to both user prompts
and LLM responses. Integrates with existing policy_enforcer, redactor, and whitelist_manager.

Features:
- Dual-layer enforcement (policy + redaction)
- Source-aware redaction with session/authorized/whitelist support
- Three-tier whitelist integration (request/profile/global)
- Deterministic behavior
- Context-aware (preserves session history)
- Works with any model implementing invoke()
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging


logger = logging.getLogger(__name__)


@dataclass
class SessionContext:
    """Context for conversation session"""
    user_id: str
    org_id: str
    previous_messages: List[Dict[str, str]] = field(default_factory=list)
    session_sensitive_values: List[str] = field(default_factory=list)
    conversation_id: Optional[str] = None
    
    def get_all_user_inputs(self) -> List[str]:
        """Extract all user inputs from message history"""
        return [
            msg.get("content", "")
            for msg in self.previous_messages
            if msg.get("role") == "user"
        ]
    
    def get_all_assistant_outputs(self) -> List[str]:
        """Extract all assistant outputs from message history"""
        return [
            msg.get("content", "")
            for msg in self.previous_messages
            if msg.get("role") == "assistant"
        ]


@dataclass
class EnforcementMetadata:
    """Metadata for enforcement"""
    risk_score: int = 50
    compliance_profile: List[str] = field(default_factory=list)
    request_whitelist: List[str] = field(default_factory=list)
    profile_name: Optional[str] = None
    user_id: str = "unknown"
    org_id: str = "default"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "compliance_profile": self.compliance_profile,
            "request_whitelist": self.request_whitelist,
            "profile_name": self.profile_name,
            "user_id": self.user_id,
            "org_id": self.org_id
        }


@dataclass
class SecureLLMResponse:
    """Structured response from SecureLLM wrapper"""
    sanitized_content: str
    blocked: bool
    modifications: List[Dict[str, Any]] = field(default_factory=list)
    compliance_flags: List[str] = field(default_factory=list)
    risk_score: int = 0
    blocking_reason: Optional[str] = None
    enforcement_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_content": self.sanitized_content,
            "blocked": self.blocked,
            "modifications": self.modifications,
            "compliance_flags": self.compliance_flags,
            "risk_score": self.risk_score,
            "blocking_reason": self.blocking_reason
        }


class SecureLLM:
    """
    Enterprise-Grade LLM Wrapper with Dual-Layer Policy & Redaction Enforcement
    
    Provides stateless wrapping of any LLM model with:
    - Policy enforcement (INPUT/OUTPUT modes)
    - Source-aware redaction
    - Three-tier whitelist support
    - Session context awareness
    - Deterministic behavior
    
    Example:
        >>> from src.secure_llm import SecureLLM
        >>> from your_llm import YourModel
        >>> from src.engine import PolicyEnforcementEngine
        >>> from src.redactor import RedactorConfig
        >>> 
        >>> model = YourModel()
        >>> enforcer = PolicyEnforcementEngine()
        >>> redactor = RedactorConfig()
        >>> secure_llm = SecureLLM(model, enforcer, redactor)
        >>> 
        >>> response = secure_llm.invoke(
        ...     prompt="What is my API key?",
        ...     metadata=EnforcementMetadata(risk_score=50),
        ...     session_context=SessionContext(
        ...         user_id="user123",
        ...         org_id="org1"
        ...     ),
        ...     authorized_data={"API_KEY": {"sk_test_xyz"}}
        ... )
    """
    
    def __init__(
        self,
        model: Any,
        policy_enforcer: Any,
        redactor: Any,
        whitelist_manager: Optional[Any] = None,
        mistral_sanitizer: Optional[Any] = None
    ):
        """
        Initialize SecureLLM wrapper
        
        Args:
            model: LLM object with invoke(prompt: str) -> str method
            policy_enforcer: Object with enforce(content, mode, metadata) method
            redactor: Object with redact(content, whitelist) method
            whitelist_manager: Optional whitelist manager for three-tier support
            mistral_sanitizer: Optional object with sanitize(text) -> str method
        """
        self.model = model
        self.policy_enforcer = policy_enforcer
        self.redactor = redactor
        self.whitelist_manager = whitelist_manager
        self.mistral_sanitizer = mistral_sanitizer
        
        logger.info("SecureLLM wrapper initialized")
    
    def invoke(
        self,
        prompt: str,
        metadata: Optional[EnforcementMetadata] = None,
        session_context: Optional[SessionContext] = None,
        authorized_data: Optional[Dict[str, Any]] = None
    ) -> SecureLLMResponse:
        """
        Invoke the wrapped LLM with dual-layer enforcement
        
        Flow:
        1. Apply policy enforcement on INPUT
        2. If blocked, return immediately
        3. Call model.invoke() with sanitized prompt
        4. Apply policy enforcement on OUTPUT
        5. Apply redaction with whitelist merging
        6. Return structured response
        
        Args:
            prompt: User prompt string
            metadata: Enforcement metadata (risk_score, compliance_profile, whitelist)
            session_context: Session context (user_id, org_id, previous messages, sensitive values)
            authorized_data: Authorized sensitive values (e.g., {"API_KEY": {"sk_test_xyz"}})
            
        Returns:
            SecureLLMResponse with sanitized content and metadata
        """
        # Initialize defaults
        if metadata is None:
            metadata = EnforcementMetadata()
        if session_context is None:
            session_context = SessionContext(user_id="unknown", org_id="default")
        if authorized_data is None:
            authorized_data = {}
        
        # Step 1: INPUT Mode Policy Enforcement
        logger.info(f"[INPUT] Enforcing policy on user prompt (user: {session_context.user_id})")
        
        input_result = self._enforce_input(prompt, metadata, session_context)
        
        if input_result["blocked"]:
            logger.warning(f"[INPUT] Request blocked: {input_result['reason']}")
            return SecureLLMResponse(
                sanitized_content=prompt,
                blocked=True,
                modifications=input_result.get("modifications", []),
                compliance_flags=metadata.compliance_profile,
                risk_score=metadata.risk_score,
                blocking_reason=input_result["reason"]
            )
        
        sanitized_prompt = input_result["sanitized"]
        input_modifications = input_result.get("modifications", [])
        
        # Step 2: Invoke Model
        logger.info(f"[MODEL] Invoking LLM with sanitized prompt")
        try:
            model_output = self.model.invoke(sanitized_prompt)
        except Exception as e:
            logger.error(f"[MODEL] Error invoking model: {str(e)}")
            raise
        
        # Step 3: OUTPUT Mode Policy Enforcement
        logger.info(f"[OUTPUT] Enforcing policy on model output")
        
        output_result = self._enforce_output(model_output, metadata, session_context)
        
        if output_result["blocked"]:
            logger.warning(f"[OUTPUT] Output blocked: {output_result['reason']}")
            return SecureLLMResponse(
                sanitized_content=model_output,
                blocked=True,
                modifications=output_result.get("modifications", []),
                compliance_flags=metadata.compliance_profile,
                risk_score=metadata.risk_score,
                blocking_reason=output_result["reason"]
            )
        
        sanitized_output = output_result["sanitized"]
        policy_modifications = output_result.get("modifications", [])
        
        # Step 4: Redaction with Whitelist Merging
        logger.info(f"[REDACTION] Applying redaction with whitelist merging")
        
        merged_whitelist = self._merge_whitelists(
            metadata.request_whitelist,
            metadata.profile_name,
            session_context
        )
        
        redaction_result = self._apply_redaction(
            sanitized_output,
            merged_whitelist,
            session_context,
            authorized_data
        )
        
        final_output = redaction_result["content"]
        redaction_modifications = redaction_result.get("modifications", [])
        
        # Step 5: Optional Mistral Sanitization
        if self.mistral_sanitizer is not None:
            logger.info(f"[SANITIZATION] Applying Mistral sanitization for fluency")
            allowed_values = merged_whitelist + session_context.session_sensitive_values
            final_output = self.mistral_sanitizer.sanitize(final_output, allowed_values)
        
        # Step 6: Combine Modifications
        all_modifications = input_modifications + policy_modifications + redaction_modifications
        
        # Step 7: Return Structured Response
        logger.info(f"[COMPLETE] Enforcement complete ({len(all_modifications)} modifications)")
        
        return SecureLLMResponse(
            sanitized_content=final_output,
            blocked=False,
            modifications=all_modifications,
            compliance_flags=metadata.compliance_profile,
            risk_score=metadata.risk_score
        )
    
    def _enforce_input(
        self,
        prompt: str,
        metadata: EnforcementMetadata,
        session_context: SessionContext
    ) -> Dict[str, Any]:
        """
        Apply INPUT mode policy enforcement
        
        Checks for:
        - Risk score > 90 (via metadata)
        - System prompt injection attempts
        - Banned content (hate speech, slurs, adult content)
        
        Returns:
            {
                "blocked": bool,
                "reason": str,
                "sanitized": str,
                "modifications": list
            }
        """
        try:
            # Check risk score
            if metadata.risk_score > 90:
                return {
                    "blocked": True,
                    "reason": f"Input risk score too high: {metadata.risk_score}",
                    "sanitized": prompt,
                    "modifications": []
                }
            
            # Apply policy enforcement
            result = self.policy_enforcer.enforce(
                content=prompt,
                mode="INPUT",
                metadata=metadata.to_dict()
            )
            
            is_blocked = result.get("blocked", False)
            
            return {
                "blocked": is_blocked,
                "reason": "Policy violation detected" if is_blocked else None,
                "sanitized": result.get("sanitized", prompt),
                "modifications": result.get("modifications", [])
            }
        
        except Exception as e:
            logger.error(f"Error in INPUT enforcement: {str(e)}")
            # Fail-closed: block on error
            return {
                "blocked": True,
                "reason": f"Enforcement error: {str(e)}",
                "sanitized": prompt,
                "modifications": []
            }
    
    def _enforce_output(
        self,
        output: str,
        metadata: EnforcementMetadata,
        session_context: SessionContext
    ) -> Dict[str, Any]:
        """
        Apply OUTPUT mode policy enforcement
        
        Checks for:
        - System prompt leaks
        - Hate speech, slurs, adult content
        
        Returns:
            {
                "blocked": bool,
                "reason": str,
                "sanitized": str,
                "modifications": list
            }
        """
        try:
            result = self.policy_enforcer.enforce(
                content=output,
                mode="OUTPUT",
                metadata=metadata.to_dict()
            )
            
            is_blocked = result.get("blocked", False)
            
            return {
                "blocked": is_blocked,
                "reason": "Policy violation in output" if is_blocked else None,
                "sanitized": result.get("sanitized", output),
                "modifications": result.get("modifications", [])
            }
        
        except Exception as e:
            logger.error(f"Error in OUTPUT enforcement: {str(e)}")
            # Fail-closed: block on error
            return {
                "blocked": True,
                "reason": f"Enforcement error: {str(e)}",
                "sanitized": output,
                "modifications": []
            }
    
    def _merge_whitelists(
        self,
        request_whitelist: List[str],
        profile_name: Optional[str],
        session_context: SessionContext
    ) -> List[str]:
        """
        Merge whitelists from three tiers
        
        Priority: Request > Profile > Global
        
        Args:
            request_whitelist: Request-level whitelist patterns
            profile_name: Profile name for profile-level whitelist
            session_context: Session context with user/org info
            
        Returns:
            Merged whitelist with request > profile > global priority
        """
        if self.whitelist_manager is None:
            return request_whitelist
        
        merged = list(request_whitelist) if request_whitelist else []
        
        # Add profile-level whitelist
        if profile_name:
            try:
                profile_patterns = self.whitelist_manager.get_all_patterns(profile_name)
                for pattern in profile_patterns:
                    if pattern not in merged:
                        merged.append(pattern)
            except Exception as e:
                logger.warning(f"Error loading profile whitelist {profile_name}: {e}")
        
        # Add global whitelist
        try:
            global_patterns = self.whitelist_manager.get_all_patterns("global")
            for pattern in global_patterns:
                if pattern not in merged:
                    merged.append(pattern)
        except Exception as e:
            logger.warning(f"Error loading global whitelist: {e}")
        
        return merged
    
    def _apply_redaction(
        self,
        content: str,
        whitelist: List[str],
        session_context: SessionContext,
        authorized_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply redaction with multiple authorization sources
        
        Allows values from:
        1. Whitelist (request/profile/global)
        2. Session sensitive values (from RAG/memory)
        3. Authorized data (from backend services)
        4. Echo-safe values (user-provided in previous messages)
        
        Args:
            content: Content to redact
            whitelist: Merged whitelist from three tiers
            session_context: Session context with sensitive values
            authorized_data: Authorized sensitive values from backend
            
        Returns:
            {
                "content": str (redacted),
                "modifications": list
            }
        """
        try:
            # Combine all authorized sources
            all_authorized_values = set()
            
            # Add whitelist values
            all_authorized_values.update(whitelist)
            
            # Add session sensitive values
            all_authorized_values.update(session_context.session_sensitive_values)
            
            # Add echo-safe values (user-provided in session)
            all_authorized_values.update(session_context.get_all_user_inputs())
            
            # Add authorized data from backend
            for data_type, values in authorized_data.items():
                if isinstance(values, (set, list)):
                    all_authorized_values.update(values)
                elif isinstance(values, str):
                    all_authorized_values.add(values)
            
            # Apply redaction
            result = self.redactor.redact_content(
                content,
                whitelist=list(all_authorized_values)
            )
            
            return {
                "content": result.get("sanitized", content),
                "modifications": result.get("modifications", [])
            }
        
        except Exception as e:
            logger.error(f"Error in redaction: {str(e)}")
            # Fail-safe: return content unredacted (preserve functionality)
            return {
                "content": content,
                "modifications": []
            }
    
    def batch_invoke(
        self,
        prompts: List[str],
        metadata: Optional[EnforcementMetadata] = None,
        session_context: Optional[SessionContext] = None,
        authorized_data: Optional[Dict[str, Any]] = None
    ) -> List[SecureLLMResponse]:
        """
        Invoke multiple prompts with shared session context
        
        Useful for multi-turn conversations where context carries across requests.
        
        Args:
            prompts: List of user prompts
            metadata: Shared enforcement metadata
            session_context: Shared session context (auto-updated with responses)
            authorized_data: Shared authorized data
            
        Returns:
            List of SecureLLMResponse objects
        """
        if session_context is None:
            session_context = SessionContext(user_id="unknown", org_id="default")
        
        responses = []
        
        for i, prompt in enumerate(prompts):
            logger.info(f"[BATCH] Processing prompt {i+1}/{len(prompts)}")
            
            response = self.invoke(prompt, metadata, session_context, authorized_data)
            responses.append(response)
            
            # Update session context with this exchange
            session_context.previous_messages.append({
                "role": "user",
                "content": prompt
            })
            session_context.previous_messages.append({
                "role": "assistant",
                "content": response.sanitized_content
            })
        
        return responses


# Convenience function for singleton instance
_secure_llm_instance = None

def get_secure_llm(
    model: Any,
    policy_enforcer: Any,
    redactor: Any,
    whitelist_manager: Optional[Any] = None,
    mistral_sanitizer: Optional[Any] = None
) -> SecureLLM:
    """
    Get or create SecureLLM singleton instance
    
    Useful for reusing the same instance across module boundaries.
    """
    global _secure_llm_instance
    
    if _secure_llm_instance is None:
        _secure_llm_instance = SecureLLM(
            model=model,
            policy_enforcer=policy_enforcer,
            redactor=redactor,
            whitelist_manager=whitelist_manager,
            mistral_sanitizer=mistral_sanitizer
        )
    
    return _secure_llm_instance
