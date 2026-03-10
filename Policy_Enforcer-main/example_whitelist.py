#!/usr/bin/env python3
"""
Example: Using the Policy Enforcer with Whitelist Feature
Shows how to test sensitive data without redaction
"""

import requests
import json

# Configuration
ENFORCER_URL = "http://localhost:8000/enforce"

def enforce_with_whitelist(content, whitelist=None, profile="DEFAULT"):
    """
    Call the policy enforcer API with optional whitelist
    
    Args:
        content: Text to enforce
        whitelist: List of values/patterns to NOT redact
        profile: Policy profile to use
    
    Returns:
        Response dict with sanitized_content and modifications
    """
    
    request_body = {
        "mode": "INPUT",
        "content": content,
        "metadata": {
            "user_id": "test_user",
            "risk_score": 0,
            "categories": [],
            "org_policy_profile": profile,
            "compliance_profile": []
        },
        "whitelist": whitelist or []
    }
    
    response = requests.post(ENFORCER_URL, json=request_body)
    return response.json()

# ============================================================================
# EXAMPLE 1: Test with API key (whitelisted)
# ============================================================================
print("\n" + "="*70)
print("EXAMPLE 1: API Key Testing with Whitelist")
print("="*70)

api_key = "gsk_abcd1234efgh5678ijkl9012mnop3456"
content1 = f"Connect to Groq API using key: {api_key}"

print(f"\nInput: {content1}")
result1 = enforce_with_whitelist(content1, whitelist=[api_key])
print(f"Output: {result1['sanitized_content']}")
print(f"Redacted: {result1['blocked']}")
print(f"Modifications: {result1['modifications']}")

# ============================================================================
# EXAMPLE 2: Same content WITHOUT whitelist (will be redacted)
# ============================================================================
print("\n" + "="*70)
print("EXAMPLE 2: Same Content Without Whitelist (Redacted)")
print("="*70)

print(f"\nInput: {content1}")
result2 = enforce_with_whitelist(content1)  # No whitelist
print(f"Output: {result2['sanitized_content']}")
print(f"Modifications: {result2['modifications']}")

# ============================================================================
# EXAMPLE 3: Multiple whitelisted values
# ============================================================================
print("\n" + "="*70)
print("EXAMPLE 3: Multiple Whitelisted Values")
print("="*70)

email = "dev@staging.company.com"
api_token = "sk_test_51234567890abcdefghijk"
content3 = f"Send results to {email} using token {api_token}"

whitelist3 = [email, api_token]
print(f"\nInput: {content3}")
print(f"Whitelist: {whitelist3}")
result3 = enforce_with_whitelist(content3, whitelist=whitelist3)
print(f"Output: {result3['sanitized_content']}")
print(f"Modifications: {result3['modifications']}")

# ============================================================================
# EXAMPLE 4: Using regex patterns in whitelist
# ============================================================================
print("\n" + "="*70)
print("EXAMPLE 4: Regex Patterns in Whitelist")
print("="*70)

content4 = "Email staging_user_1@test.com, staging_user_2@test.com, or real_user@real.com"
# Only whitelist the staging emails
whitelist4 = ["staging_user_.*@test.com"]  # Regex pattern

print(f"\nInput: {content4}")
print(f"Whitelist: {whitelist4}")
result4 = enforce_with_whitelist(content4, whitelist=whitelist4)
print(f"Output: {result4['sanitized_content']}")
print(f"Modifications: {result4['modifications']}")

# ============================================================================
# EXAMPLE 5: Different profiles
# ============================================================================
print("\n" + "="*70)
print("EXAMPLE 5: Using Policy Profile 'FINTECH'")
print("="*70)

# FINTECH profile might have different thresholds
content5 = "Process payment using card 4532123456789010"
print(f"\nInput: {content5}")
result5 = enforce_with_whitelist(content5, profile="FINTECH")
print(f"Output: {result5['sanitized_content']}")
print(f"Modifications: {result5['modifications']}")

# ============================================================================
# Practical Workflow: Development vs Production
# ============================================================================
print("\n" + "="*70)
print("WORKFLOW: Dev (with whitelist) vs Prod (without)")
print("="*70)

print("\n--- DEVELOPMENT (testing with real keys) ---")
dev_api_key = "gsk_dev_1234567890abcdefghijkl"
dev_content = f"Test LLM integration with key: {dev_api_key}"
dev_result = enforce_with_whitelist(dev_content, whitelist=[dev_api_key])
print(f"Input: {dev_content}")
print(f"Output: {dev_result['sanitized_content']}")
print(f"✓ Key preserved for local testing")

print("\n--- PRODUCTION (no whitelist, all redacted) ---")
prod_result = enforce_with_whitelist(dev_content)  # No whitelist in production!
print(f"Input: {dev_content}")
print(f"Output: {prod_result['sanitized_content']}")
print(f"✓ Key redacted for production safety")

print("\n" + "="*70)
