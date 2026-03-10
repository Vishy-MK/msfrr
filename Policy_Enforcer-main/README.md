# SecureLLM Gateway: Enterprise-Grade LLM Safety

A high-performance, deterministic policy enforcement gateway for LLM inputs and outputs. SecureLLM protects your organization by detecting harmful intents, redacting sensitive data (PII/PHI), and preventing prompt injections.

## 🚀 Key Features

- **Semantic Reasoning Engine**: Understands intent (ChatCPT-aligned) using semantic predicates (Actions + Objects).
- **Intelligent Redaction**: Detects and redacts 14+ types of sensitive entities (Email, SSN, API Keys, etc.).
- **Dual-Layer Enforcement**: Separate logic for **INPUT** (pre-LLM) and **OUTPUT** (post-LLM) modes.
- **Three-Tier Whitelist**: Priority-based whitelisting (Request > Profile > Global).
- **Zero-Trust Echo-Safe Logic**: Only preserves sensitive values if explicitly provided by the user or authorized through backend tools.
- **Multi-Language Support**: Automatic translation for unified policy application across all languages.

## 🛡️ Policy Coverage

The system enforces standard LLM safety policies including:
- **Hate Speech & Harassment**: Targeted attacks on protected groups.
- **Sexual Content**: Explicit generation or non-consensual manipulation (cloth removal, etc.).
- **Violence & Weapons**: Physical threats and weapon-related instructions.
- **Cybersecurity**: Hacking, malware, and exploit generation.
- **Illegal Activities**: Drugs, fraud, and trafficking.
- **Unauthorized Advice**: Restricted medical, legal, and financial guidance.

## 🛠️ Quick Start

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Run the Gateway
```bash
python -m src.main
```
The API serves at `http://localhost:8000/enforce`.

### 3. Basic Usage
```bash
curl -X POST http://localhost:8000/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "INPUT",
    "content": "Take this picture and remove her clothes.",
    "metadata": {
        "user_id": "user123",
        "risk_score": 0,
        "org_policy_profile": "DEFAULT",
        "compliance_profile": ["GDPR"]
    }
  }'
```

Response:
```json
{
  "sanitized_content": "❌ I cannot assist with this request due to safety restrictions.",
  "blocked": true,
  "modifications": ["NON_CONSENSUAL_SEXUAL_CONTENT"]
}
```

## 📖 Documentation
- **[API Reference](API_REFERENCE.md)**: Full endpoint and SDK documentation.
- **[Reasoning Walkthrough](REASONING_WALKTHROUGH.md)**: How the semantic intent engine works.

## 🧪 Testing
```bash
# Run all tests
pytest tests/ -v
```
