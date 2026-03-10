# SecureLLM API Reference

Complete API documentation for all SecureLLM classes and methods.

## Table of Contents

1. [SessionContext](#sessioncontext)
2. [EnforcementMetadata](#enforcementmetadata)
3. [SecureLLMResponse](#securellmresponse)
4. [SecureLLM](#securellm)
5. [Helper Functions](#helper-functions)
6. [Type Definitions](#type-definitions)

---

## SessionContext

Immutable dataclass representing conversation session and context.

### Definition

```python
@dataclass
class SessionContext:
    user_id: str
    org_id: str
    previous_messages: List[Dict[str, str]] = field(default_factory=list)
    session_sensitive_values: List[str] = field(default_factory=list)
    conversation_id: Optional[str] = None
    user_metadata: Optional[Dict[str, Any]] = None
```

### Attributes

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | `str` | ✓ | Unique identifier for the user |
| `org_id` | `str` | ✓ | Organization/tenant identifier |
| `previous_messages` | `List[Dict]` | | Message history (role + content) |
| `session_sensitive_values` | `List[str]` | | Values from RAG/memory to preserve |
| `conversation_id` | `str` | | Unique ID for this conversation |
| `user_metadata` | `Dict[str, Any]` | | Additional user Context |

### Methods

#### `get_all_user_inputs() -> List[str]`

Extract all user messages from conversation history.

**Returns**: List of user message strings

**Example**:
```python
session = SessionContext(
    user_id="user1",
    org_id="org1",
    previous_messages=[
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi"},
        {"role": "user", "content": "How are you?"}
    ]
)

user_inputs = session.get_all_user_inputs()
# → ["Hello", "How are you?"]
```

#### `get_all_assistant_outputs() -> List[str]`

Extract all assistant messages from conversation history.

**Returns**: List of assistant message strings

**Example**:
```python
outputs = session.get_all_assistant_outputs()
# → ["Hi"]
```

### Usage Examples

#### Basic Session

```python
session = SessionContext(
    user_id="analyst_789",
    org_id="fintech_corp"
)
```

#### Session with History

```python
session = SessionContext(
    user_id="analyst_789",
    org_id="fintech_corp",
    previous_messages=[
        {"role": "user", "content": "Analyze account 123"},
        {"role": "assistant", "content": "Account analysis..."},
        {"role": "user", "content": "Show risk factors"}
    ],
    conversation_id="conv_xyz789"
)
```

#### Session with RAG Values

```python
session = SessionContext(
    user_id="user1",
    org_id="org1",
    session_sensitive_values=[
        "db_password_secure",
        "api_key_sk_prod",
        "customer_email@example.com"
    ]
)
```

---

## EnforcementMetadata

Configuration for policy enforcement rules and thresholds.

### Definition

```python
@dataclass
class EnforcementMetadata:
    risk_score: int = 50
    compliance_profile: List[str] = field(default_factory=list)
    request_whitelist: List[str] = field(default_factory=list)
    profile_name: Optional[str] = None
    user_id: str = "unknown"
    org_id: str = "default"
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None
```

### Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `risk_score` | `int` | 50 | 0-100, >90 blocks INPUT (fail-closed) |
| `compliance_profile` | `List[str]` | [] | Policy profiles to apply (audit purpose) |
| `request_whitelist` | `List[str]` | [] | One-time whitelist patterns (request level) |
| `profile_name` | `str` | None | Profile for profile-level whitelist lookup |
| `user_id` | `str` | "unknown" | User identifier (audit) |
| `org_id` | `str` | "default" | Organization identifier (audit) |
| `request_id` | `str` | None | Unique request identifier |
| `timestamp` | `datetime` | None | Request timestamp |

### Methods

#### `to_dict() -> Dict[str, Any]`

Convert metadata to JSON-serializable dictionary.

**Returns**: Dictionary with string keys and JSON-serializable values

**Example**:
```python
metadata = EnforcementMetadata(
    risk_score=75,
    compliance_profile=["FINTECH"],
    user_id="user123"
)

meta_dict = metadata.to_dict()
# → {
#     "risk_score": 75,
#     "compliance_profile": ["FINTECH"],
#     "user_id": "user123",
#     ...
#   }
```

### Risk Score Interpretation

```python
risk_score = 0      # No risk
risk_score = 50     # Default/moderate
risk_score = 75     # Elevated risk
risk_score = 90     # Critical
risk_score = 95     # Blocks (fail-closed)
```

### Compliance Profile Examples

```python
# FINTECH
EnforcementMetadata(compliance_profile=["FINTECH"])

# HEALTHCARE (HIPAA)
EnforcementMetadata(compliance_profile=["HEALTHCARE", "HIPAA"])

# DEFENSE
EnforcementMetadata(compliance_profile=["DEFENSE", "CLASSIFIED"])

# EDUCATION (FERPA)
EnforcementMetadata(compliance_profile=["EDTECH", "FERPA"])

# Multiple profiles
EnforcementMetadata(compliance_profile=["FINTECH", "SOC2", "PCI-DSS"])
```

### Usage Examples

#### Basic Metadata

```python
metadata = EnforcementMetadata(risk_score=50)
```

#### With Compliance

```python
metadata = EnforcementMetadata(
    risk_score=65,
    compliance_profile=["FINTECH", "SOC2"],
    profile_name="FINTECH"
)
```

#### With Request Whitelist

```python
metadata = EnforcementMetadata(
    risk_score=50,
    request_whitelist=[
        "admin@company.com",
        "service@internal.com",
        "sk_test_.*"  # Regex supported
    ]
)
```

---

## SecureLLMResponse

Structured response from SecureLLM invocation.

### Definition

```python
@dataclass
class SecureLLMResponse:
    sanitized_content: str
    blocked: bool
    modifications: List[Dict[str, Any]] = field(default_factory=list)
    compliance_flags: List[str] = field(default_factory=list)
    risk_score: int = 0
    blocking_reason: Optional[str] = None
    enforcement_metadata: Optional[Dict[str, Any]] = None
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `sanitized_content` | `str` | Final output after enforcement and redaction |
| `blocked` | `bool` | True if request/response was rejected |
| `modifications` | `List[Dict]` | Applied redactions and changes |
| `compliance_flags` | `List[str]` | Applied compliance profiles |
| `risk_score` | `int` | Input risk score |
| `blocking_reason` | `str` | Why request was blocked (if blocked) |
| `enforcement_metadata` | `Dict` | Detailed enforcement information |

### Methods

#### `to_dict() -> Dict[str, Any]`

Convert response to JSON-serializable dictionary for API responses.

**Returns**: Dictionary suitable for JSON serialization

**Example**:
```python
response = secure_llm.invoke(prompt)

response_dict = response.to_dict()
# → {
#     "sanitized_content": "Response...",
#     "blocked": false,
#     "modifications": [...],
#     "compliance_flags": ["FINTECH"],
#     "risk_score": 50
#   }

# Use in API response
return {"data": response_dict}
```

### Modification Format

Each modification is a dictionary:

```python
{
    "type": "REDACTION",           # Type of modification
    "original": "api_key_xyz",     # Original value
    "redacted": "[REDACTED_API]",  # Replacement
    "reason": "API_KEY",           # Why redacted
    "source": "redaction_engine"   # Tool that made change
}
```

### Usage Examples

#### Handle Blocked Response

```python
response = secure_llm.invoke(prompt)

if response.blocked:
    logger.warning(f"Blocked: {response.blocking_reason}")
    return {"error": response.blocking_reason}, 403

return {"content": response.sanitized_content}
```

#### Check Modifications

```python
if len(response.modifications) > 5:
    logger.warning(f"Many redactions: {response.modifications}")

for mod in response.modifications:
    print(f"Redacted: {mod['original']} ({mod['reason']})")
```

#### Serialize for Database

```python
import json

data = {
    "prompt": original_prompt,
    "response": response.sanitized_content,
    "enforcement": response.to_dict(),
    "timestamp": datetime.utcnow().isoformat()
}

json_str = json.dumps(data)  # Fully serializable
```

---

## SecureLLM

Main wrapper class for LLM enforcement and redaction.

### Definition

```python
class SecureLLM:
    def __init__(
        self,
        model: Any,
        policy_enforcer: Any,
        redactor: Any,
        whitelist_manager: Optional[Any] = None,
        mistral_sanitizer: Optional[Any] = None
    ) -> None
```

### Instance Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `model` | `Any` | LLM with `invoke(prompt: str) -> str` method |
| `policy_enforcer` | `Any` | Enforcer with `enforce()` method |
| `redactor` | `Any` | Redactor with `redact_content()` method |
| `whitelist_manager` | `Any` | Optional whitelist manager |
| `mistral_sanitizer` | `Any` | Optional fluency sanitizer |

### Methods

#### `invoke(prompt, metadata=None, session_context=None, authorized_data=None) -> SecureLLMResponse`

Main method to invoke LLM with dual-layer enforcement.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `prompt` | `str` | ✓ | User message to process |
| `metadata` | `EnforcementMetadata` | | Enforcement configuration |
| `session_context` | `SessionContext` | | Conversation context |
| `authorized_data` | `Dict[str, List[str]]` | | Backend data to whitelist |

**Returns**: `SecureLLMResponse` with sanitized content and metadata

**Raises**:
- `ValueError`: If prompt is invalid or enforcement fails
- `RuntimeError`: If model invocation fails

**Processing Steps**:
1. INPUT policy enforcement (check risk, system prompts)
2. Model invocation with sanitized prompt
3. OUTPUT policy enforcement (check response)
4. Whitelist merging (request > profile > global)
5. Multi-source redaction
6. Optional sanitization
7. Return structured response

**Example**:
```python
response = secure_llm.invoke(
    prompt="What is my API key?",
    metadata=EnforcementMetadata(
        risk_score=60,
        compliance_profile=["FINTECH"]
    ),
    session_context=SessionContext(
        user_id="user123",
        org_id="org456"
    ),
    authorized_data={
        "API_KEY": ["sk_prod_xyz"]
    }
)

if response.blocked:
    print(f"Blocked: {response.blocking_reason}")
else:
    print(f"Response: {response.sanitized_content}")
    print(f"Mods: {len(response.modifications)}")
```

---

#### `batch_invoke(prompts, metadata=None, session_context=None, authorized_data=None) -> List[SecureLLMResponse]`

Process multiple prompts with shared session context.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `prompts` | `List[str]` | ✓ | Multiple prompts to invoke |
| `metadata` | `EnforcementMetadata` | | Enforcement configuration |
| `session_context` | `SessionContext` | | Shared conversation context |
| `authorized_data` | `Dict[str, List[str]]` | | Backend data |

**Returns**: List of `SecureLLMResponse` objects (same length as prompts)

**Behavior**:
- Each response added to session context
- Session context persists across batch
- All responses share enforcement metadata
- Fails safely on individual errors

**Example**:
```python
import time

prompts = [
    "Initialize analysis",
    "What sensitive data was found?",
    "Generate report"
]

session = SessionContext(
    user_id="analyst",
    org_id="fintech",
    previous_messages=[]
)

responses = secure_llm.batch_invoke(
    prompts=prompts,
    session_context=session
)

for i, (prompt, response) in enumerate(zip(prompts, responses)):
    print(f"[{i}] {prompt}")
    if response.blocked:
        print(f"    BLOCKED: {response.blocking_reason}")
    else:
        print(f"    Response: {response.sanitized_content[:100]}...")

# Session updated with all responses
print(f"Session history size: {len(session.previous_messages)}")
```

---

### Private Methods

#### `_enforce_input(prompt, metadata, session_context) -> Dict`

Internal: Check input enforcement rules.

**Returns**:
```python
{
    "blocked": bool,        # Whether to block
    "reason": str,          # Why (if blocked)
    "risk_score": int,      # Computed/provided risk
    "violations": [str]     # Policy violations
}
```

---

#### `_enforce_output(output, metadata, session_context) -> Dict`

Internal: Check output enforcement rules.

**Returns**: Same as `_enforce_input`

---

#### `_merge_whitelists(request_whitelist, profile_name, session_context) -> List[str]`

Internal: Merge three-tier whitelist with priority.

**Priority**:
1. Request-level (highest)
2. Profile-level
3. Global (lowest)
4. Session-sensitive values
5. Echo-safe values

**Returns**: Merged whitelist patterns

---

#### `_apply_redaction(content, whitelist, session_context, authorized_data) -> str`

Internal: Apply multi-source redaction.

**Authorization sources** (checked in order):
1. Whitelist patterns
2. Session sensitive values
3. Authorized backend data
4. Echo-safe (previous user messages)

**Returns**: Redacted content

---

## Helper Functions

#### `get_secure_llm() -> SecureLLM`

Singleton accessor for SecureLLM instance (requires prior initialization).

**Returns**: Global SecureLLM instance

**Example**:
```python
# First, initialize
from src.secure_llm import SecureLLM

secure_llm = SecureLLM(model, enforcer, redactor)

# Later, in different module
from src.secure_llm import get_secure_llm

llm = get_secure_llm()  # Same instance
response = llm.invoke(prompt)
```

---

## Type Definitions

### Message Format

```python
Message = Dict[str, str]  # {"role": "user" | "assistant", "content": str}
```

### Whitelist Format

```python
Whitelist = List[str]  # Exact strings or regex patterns
```

### Authorized Data Format

```python
AuthorizedData = Dict[str, List[str]]
# Example:
{
    "API_KEY": ["sk_prod_xyz", "sk_test_.*"],
    "EMAIL": ["admin@company.com", "service@internal.com"],
    "DATABASE_CREDS": ["db_pass_xyz"],
    "PHONE": ["+1-555-0123"],
    "SSN": ["123-45-6789"]
}
```

### Enforcement Result Format

```python
EnforcementResult = Dict[str, Any]
# Example:
{
    "blocked": false,
    "violations": [],
    "risk_score": 50,
    "details": {...}
}
```

---

## Complete Example

```python
from src.secure_llm import SecureLLM, SessionContext, EnforcementMetadata
from src.engine import PolicyEnforcementEngine
from src.redactor import RedactorConfig
from src.whitelist_manager import get_whitelist_manager

# === 1. Initialize Components ===
model = YourLLMModel()  # Has invoke() method
enforcer = PolicyEnforcementEngine()
redactor = RedactorConfig()
whitelist_mgr = get_whitelist_manager()

# === 2. Create SecureLLM ===
secure_llm = SecureLLM(
    model=model,
    policy_enforcer=enforcer,
    redactor=redactor,
    whitelist_manager=whitelist_mgr
)

# === 3. Create Session ===
session = SessionContext(
    user_id="analyst_123",
    org_id="fintech_corp",
    previous_messages=[
        {"role": "user", "content": "Show me transaction data"},
        {"role": "assistant", "content": "Here's the data..."}
    ],
    session_sensitive_values=[
        "customer_email@example.com",
        "account_number_12345"
    ]
)

# === 4. Create Metadata ===
metadata = EnforcementMetadata(
    risk_score=65,
    compliance_profile=["FINTECH", "SOC2"],
    request_whitelist=["admin@company.com"],
    profile_name="FINTECH",
    user_id="analyst_123",
    org_id="fintech_corp"
)

# === 5. Define Authorized Data ===
authorized_data = {
    "API_KEY": ["sk_service_xyz"],
    "EMAIL": ["service@internal.com"],
    "DATABASE_CREDS": ["db_prod_key"]
}

# === 6. Invoke with Enforcement ===
response = secure_llm.invoke(
    prompt="What are the top 5 high-risk transactions?",
    metadata=metadata,
    session_context=session,
    authorized_data=authorized_data
)

# === 7. Handle Response ===
if response.blocked:
    logger.error(f"Request blocked: {response.blocking_reason}")
    return {"error": response.blocking_reason}, 403

logger.info(f"Enforcement complete: {len(response.modifications)} modifications")

return {
    "response": response.sanitized_content,
    "modifications": response.modifications,
    "compliance": response.compliance_flags,
    "risk_score": response.risk_score
}
```

---

## Error Handling

```python
try:
    response = secure_llm.invoke(prompt)
except ValueError as e:
    # Invalid input
    logger.error(f"Invalid input: {e}")
    return {"error": "Invalid input"}, 400
except RuntimeError as e:
    # Model or enforcement critical error
    logger.error(f"Runtime error: {e}")
    return {"error": "Processing error"}, 500
```

---

## Testing

```python
from unittest.mock import Mock
from src.secure_llm import SecureLLM

# Create mocks
model = Mock()
model.invoke = Mock(return_value="Test response")

enforcer = Mock()
enforcer.enforce = Mock(return_value={"blocked": False})

redactor = Mock()
redactor.redact_content = Mock(return_value="Test response")

# Create SecureLLM
secure_llm = SecureLLM(model, enforcer, redactor)

# Test
response = secure_llm.invoke("Test prompt")
assert response.blocked == False
assert response.sanitized_content == "Test response"
```

Done!
