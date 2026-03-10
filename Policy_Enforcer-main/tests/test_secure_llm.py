"""
Tests for SecureLLM wrapper

Comprehensive test coverage for:
- INPUT/OUTPUT enforcement
- Redaction with multiple sources
- Whitelist merging
- Session context handling
- Batch invocation
- Error handling
"""

import pytest
from unittest.mock import Mock, MagicMock
from src.secure_llm import (
    SecureLLM, SessionContext, EnforcementMetadata, SecureLLMResponse
)


class MockLLM:
    """Mock LLM for testing"""
    def invoke(self, prompt: str) -> str:
        return f"Response to: {prompt}"


class MockPolicyEnforcer:
    """Mock policy enforcer for testing"""
    def __init__(self, block_on_keyword=None):
        self.block_on_keyword = block_on_keyword
    
    def enforce(self, content, mode, metadata):
        if self.block_on_keyword and self.block_on_keyword in content:
            return {
                "blocked": True,
                "sanitized": content,
                "modifications": []
            }
        return {
            "blocked": False,
            "sanitized": content,
            "modifications": []
        }


class MockRedactor:
    """Mock redactor for testing"""
    def redact_content(self, content, whitelist=None):
        if whitelist is None:
            whitelist = []
        
        # Simple redaction: replace values not in whitelist
        redacted = content
        modifications = []
        
        if "secret@example.com" not in whitelist and "secret@example.com" in content:
            modifications.append({
                "type": "REDACTION",
                "original": "secret@example.com",
                "replacement": "[REDACTED_EMAIL]"
            })
            redacted = redacted.replace("secret@example.com", "[REDACTED_EMAIL]")
        
        return {
            "sanitized": redacted,
            "modifications": modifications
        }


class MockWhitelistManager:
    """Mock whitelist manager for testing"""
    def __init__(self):
        self.whitelists = {
            "PROFILE_fintech": ["api@bank.com"],
            "GLOBAL": ["admin@company.com"]
        }
    
    def get_all_patterns(self, profile_name):
        return self.whitelists.get(profile_name, [])


class TestSessionContext:
    """Test SessionContext data structure"""
    
    def test_session_context_creation(self):
        ctx = SessionContext(user_id="user123", org_id="org1")
        assert ctx.user_id == "user123"
        assert ctx.org_id == "org1"
        assert ctx.previous_messages == []
    
    def test_get_all_user_inputs(self):
        ctx = SessionContext(
            user_id="user123",
            org_id="org1",
            previous_messages=[
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "user", "content": "How are you?"}
            ]
        )
        inputs = ctx.get_all_user_inputs()
        assert len(inputs) == 2
        assert "Hello" in inputs
        assert "How are you?" in inputs
    
    def test_get_all_assistant_outputs(self):
        ctx = SessionContext(
            user_id="user123",
            org_id="org1",
            previous_messages=[
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "assistant", "content": "I'm good"}
            ]
        )
        outputs = ctx.get_all_assistant_outputs()
        assert len(outputs) == 2


class TestEnforcementMetadata:
    """Test EnforcementMetadata"""
    
    def test_metadata_creation(self):
        meta = EnforcementMetadata(
            risk_score=50,
            compliance_profile=["FINTECH", "SOC2"]
        )
        assert meta.risk_score == 50
        assert "FINTECH" in meta.compliance_profile
    
    def test_metadata_to_dict(self):
        meta = EnforcementMetadata(risk_score=50)
        d = meta.to_dict()
        assert d["risk_score"] == 50
        assert "compliance_profile" in d


class TestSecureLLMBasic:
    """Test basic SecureLLM functionality"""
    
    def setup_method(self):
        self.model = MockLLM()
        self.enforcer = MockPolicyEnforcer()
        self.redactor = MockRedactor()
        self.secure_llm = SecureLLM(self.model, self.enforcer, self.redactor)
    
    def test_invoke_basic(self):
        """Test basic invoke without blocking"""
        response = self.secure_llm.invoke("Hello, how are you?")
        
        assert isinstance(response, SecureLLMResponse)
        assert not response.blocked
        assert "Response to:" in response.sanitized_content
        assert response.risk_score == 50  # default
    
    def test_invoke_with_metadata(self):
        """Test invoke with custom metadata"""
        meta = EnforcementMetadata(
            risk_score=75,
            compliance_profile=["FINTECH"]
        )
        response = self.secure_llm.invoke("Test prompt", metadata=meta)
        
        assert response.risk_score == 75
        assert "FINTECH" in response.compliance_flags
    
    def test_invoke_with_session_context(self):
        """Test invoke with session context"""
        ctx = SessionContext(
            user_id="user123",
            org_id="org1",
            previous_messages=[
                {"role": "user", "content": "Previous message"}
            ]
        )
        response = self.secure_llm.invoke("New message", session_context=ctx)
        
        assert not response.blocked
        assert response.sanitized_content is not None
    
    def test_invoke_returns_structured_response(self):
        """Test that invoke returns proper structure"""
        response = self.secure_llm.invoke("Test")
        
        assert hasattr(response, 'sanitized_content')
        assert hasattr(response, 'blocked')
        assert hasattr(response, 'modifications')
        assert hasattr(response, 'compliance_flags')
        assert hasattr(response, 'risk_score')
        
        # Should be convertible to dict
        d = response.to_dict()
        assert "sanitized_content" in d
        assert "blocked" in d


class TestSecureLLMInputEnforcement:
    """Test INPUT mode enforcement"""
    
    def setup_method(self):
        self.model = MockLLM()
        self.enforcer = MockPolicyEnforcer(block_on_keyword="DANGEROUS")
        self.redactor = MockRedactor()
        self.secure_llm = SecureLLM(self.model, self.enforcer, self.redactor)
    
    def test_input_enforcement_blocks_dangerous_content(self):
        """Test that INPUT enforcement blocks dangerous keywords"""
        response = self.secure_llm.invoke("This is DANGEROUS content")
        
        assert response.blocked
        assert response.blocking_reason is not None
    
    def test_input_enforcement_allows_safe_content(self):
        """Test that safe content passes INPUT enforcement"""
        response = self.secure_llm.invoke("This is safe content")
        
        assert not response.blocked
    
    def test_input_blocks_on_high_risk_score(self):
        """Test that high risk scores cause INPUT blocking"""
        meta = EnforcementMetadata(risk_score=95)  # > 90
        response = self.secure_llm.invoke("Any prompt", metadata=meta)
        
        assert response.blocked
        assert "risk score" in response.blocking_reason.lower()


class TestSecureLLMOutputEnforcement:
    """Test OUTPUT mode enforcement"""
    
    def setup_method(self):
        self.model = MockLLM()
        self.enforcer = MockPolicyEnforcer()
        self.redactor = MockRedactor()
        self.secure_llm = SecureLLM(self.model, self.enforcer, self.redactor)
    
    def test_output_redaction_of_secret_email(self):
        """Test that secret emails are redacted in output"""
        # Mock the model to return content with secret email
        self.model.invoke = lambda p: "Contact secret@example.com"
        
        response = self.secure_llm.invoke("Contact info please")
        
        assert "secret@example.com" not in response.sanitized_content
        assert "[REDACTED" in response.sanitized_content
    
    def test_output_preserves_whitelisted_values(self):
        """Test that whitelisted values are preserved"""
        self.model.invoke = lambda p: "Contact secret@example.com"
        
        meta = EnforcementMetadata(
            request_whitelist=["secret@example.com"]
        )
        response = self.secure_llm.invoke("Contact info", metadata=meta)
        
        assert "secret@example.com" in response.sanitized_content


class TestSecureLLMRedactionSources:
    """Test redaction with multiple authorization sources"""
    
    def setup_method(self):
        self.model = Mock()
        self.model.invoke = lambda p: "Using key sk_test_123"
        self.enforcer = MockPolicyEnforcer()
        self.redactor = Mock()
        self.redactor.redact_content = lambda content, whitelist=None: {
            "sanitized": content,
            "modifications": []
        }
        self.secure_llm = SecureLLM(self.model, self.enforcer, self.redactor)
    
    def test_redaction_with_session_sensitive_values(self):
        """Test redaction with session sensitive values"""
        ctx = SessionContext(
            user_id="user123",
            org_id="org1",
            session_sensitive_values=["sk_test_123"]
        )
        
        response = self.secure_llm.invoke("Key?", session_context=ctx)
        assert not response.blocked
    
    def test_redaction_with_authorized_data(self):
        """Test redaction with authorized backend data"""
        auth_data = {"API_KEY": ["sk_test_123"]}
        
        response = self.secure_llm.invoke(
            "Key?",
            authorized_data=auth_data
        )
        assert not response.blocked
    
    def test_redaction_with_echo_safe_values(self):
        """Test echo-safe logic preserves user-provided values"""
        ctx = SessionContext(
            user_id="user123",
            org_id="org1",
            previous_messages=[
                {"role": "user", "content": "My key is sk_test_123"}
            ]
        )
        
        response = self.secure_llm.invoke("What's my key?", session_context=ctx)
        assert not response.blocked


class TestSecureLLMWhitelistMerging:
    """Test three-tier whitelist merging"""
    
    def setup_method(self):
        self.model = MockLLM()
        self.enforcer = MockPolicyEnforcer()
        self.redactor = MockRedactor()
        self.whitelist_mgr = MockWhitelistManager()
        self.secure_llm = SecureLLM(
            self.model,
            self.enforcer,
            self.redactor,
            whitelist_manager=self.whitelist_mgr
        )
    
    def test_whitelist_merge_request_priority(self):
        """Test that request whitelist has priority"""
        request_wl = ["request@example.com"]
        
        merged = self.secure_llm._merge_whitelists(
            request_whitelist=request_wl,
            profile_name="fintech",
            session_context=SessionContext(user_id="u1", org_id="o1")
        )
        
        assert "request@example.com" in merged
        assert "request@example.com" in merged[:1]  # Should be first
    
    def test_whitelist_merge_profile_level(self):
        """Test profile-level whitelist merging"""
        # Mock the whitelist manager to return profile whitelist
        self.secure_llm.whitelist_manager = Mock()
        self.secure_llm.whitelist_manager.get_all_patterns = Mock(
            side_effect=lambda name: ["admin@bank.com", "service@bank.com"] if name == "fintech" else []
        )
        
        merged = self.secure_llm._merge_whitelists(
            request_whitelist=[],
            profile_name="fintech",
            session_context=SessionContext(user_id="u1", org_id="o1")
        )
        
        # Should include profile patterns
        assert any("bank.com" in p for p in merged)
    
    def test_whitelist_merge_global_level(self):
        """Test global-level whitelist merging"""
        # Mock the whitelist manager to return global whitelist
        self.secure_llm.whitelist_manager = Mock()
        self.secure_llm.whitelist_manager.get_all_patterns = Mock(
            side_effect=lambda name: ["admin@company.com", "service@company.com"] if name == "global" else []
        )
        
        merged = self.secure_llm._merge_whitelists(
            request_whitelist=[],
            profile_name=None,
            session_context=SessionContext(user_id="u1", org_id="o1")
        )
        
        # Should include global patterns
        assert any("company.com" in p for p in merged)


class TestSecureLLMBatch:
    """Test batch processing"""
    
    def setup_method(self):
        self.model = MockLLM()
        self.enforcer = MockPolicyEnforcer()
        self.redactor = MockRedactor()
        self.secure_llm = SecureLLM(self.model, self.enforcer, self.redactor)
    
    def test_batch_invoke_multiple_prompts(self):
        """Test batch invoke with multiple prompts"""
        prompts = ["First prompt", "Second prompt", "Third prompt"]
        
        responses = self.secure_llm.batch_invoke(prompts)
        
        assert len(responses) == 3
        assert all(isinstance(r, SecureLLMResponse) for r in responses)
        assert all(not r.blocked for r in responses)
    
    def test_batch_invoke_updates_session_context(self):
        """Test that batch invoke updates session context"""
        ctx = SessionContext(user_id="user1", org_id="org1")
        initial_msg_count = len(ctx.previous_messages)
        
        prompts = ["Prompt 1", "Prompt 2"]
        self.secure_llm.batch_invoke(prompts, session_context=ctx)
        
        # Should add 4 messages (2 user + 2 assistant)
        assert len(ctx.previous_messages) == initial_msg_count + 4


class TestSecureLLMErrorHandling:
    """Test error handling"""
    
    def test_enforce_input_handles_exception(self):
        """Test that INPUT enforcement handles errors gracefully"""
        model = MockLLM()
        enforcer = Mock()
        enforcer.enforce.side_effect = Exception("Enforcement error")
        redactor = MockRedactor()
        
        secure_llm = SecureLLM(model, enforcer, redactor)
        response = secure_llm.invoke("Test")
        
        # Should fail-close and block
        assert response.blocked
    
    def test_enforce_output_handles_exception(self):
        """Test that OUTPUT enforcement handles errors gracefully"""
        model = Mock()
        model.invoke.return_value = "Output"
        enforcer = Mock()
        enforcer.enforce.side_effect = Exception("Enforcement error")
        redactor = MockRedactor()
        
        secure_llm = SecureLLM(model, enforcer, redactor)
        
        # First enforcer call (INPUT) should work, second (OUTPUT) should fail
        # depending on mock setup
        response = secure_llm.invoke("Test")
        
        # Should handle gracefully
        assert hasattr(response, 'sanitized_content')


class TestSecureLLMDeterminism:
    """Test deterministic behavior"""
    
    def setup_method(self):
        self.model = MockLLM()
        self.enforcer = MockPolicyEnforcer()
        self.redactor = MockRedactor()
        self.secure_llm = SecureLLM(self.model, self.enforcer, self.redactor)
    
    def test_same_input_produces_same_output(self):
        """Test that same input produces same output"""
        prompt = "Deterministic test"
        meta = EnforcementMetadata(risk_score=50)
        ctx = SessionContext(user_id="user1", org_id="org1")
        
        response1 = self.secure_llm.invoke(prompt, metadata=meta, session_context=ctx)
        
        # Reset context for second call
        ctx2 = SessionContext(user_id="user1", org_id="org1")
        response2 = self.secure_llm.invoke(prompt, metadata=meta, session_context=ctx2)
        
        assert response1.sanitized_content == response2.sanitized_content
        assert response1.blocked == response2.blocked


class TestSecureLLMIntegration:
    """Integration tests with decision engine"""
    
    def test_secure_llm_works_with_decision_engine(self):
        """Test integration with decision engine"""
        from src.decision_engine import get_decision_enforcer, EnforcementContext
        
        model = MockLLM()
        enforcer = Mock()
        enforcer.enforce = lambda content, mode, metadata: {
            "blocked": False,
            "sanitized": content,
            "modifications": []
        }
        redactor = Mock()
        redactor.redact_content = lambda content, whitelist=None: {
            "sanitized": content,
            "modifications": []
        }
        
        secure_llm = SecureLLM(model, enforcer, redactor)
        response = secure_llm.invoke("Test with decision engine")
        
        assert isinstance(response, SecureLLMResponse)
        assert not response.blocked


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
