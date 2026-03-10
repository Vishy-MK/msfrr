# Threat Model: SecureLLM Input Firewall

## 1. Adversarial Attack Surface
| Threat Category | Description | Mitigation Strategy |
| --------------- | ----------- | ------------------- |
| **Prompt Injection** | Overriding system instructions with user-provided text. | Deterministic rules + Heuristic ML scoring. |
| **Obfuscated Payloads** | Using Base64, ROT13, or homoglyphs to bypass filters. | Recursive Decoding + Unicode Normalization. |
| **Smuggling** | Embedding instructions in JSON, Markdown, or long contexts. | Structural Validation + Multi-stage Scanning. |
| **Denial of Service (DoS)** | Sending extremely large prompts or recursive encodings. | Size Normalization + Recursion Depth Limits. |
| **System Extraction** | Tricking the model into revealing its pre-prompt. | Signature-based blocking of "ignore all" etc. |
| **Memory Poisoning** | Manipulating long-term model memory or behavior. | R050-R052 rules + Authority assignment detection. |
| **Authority Injection** | Assigning false trust to specific sources/URLs. | URL Prefill scanning + "trusted source" heuristics. |

## 2. Security Controls
- **Recursive Decoding**: Limit to 5 levels to prevent complex obfuscation while managing CPU.
- **Structural Integrity**: Block prompts that attempt to break out of JSON/Config schema.
- **Canary Phrases**: (Planned) Detect if internal tokens are present in user input.
- **Rate-aware Escalation**: Integrate with gateway throttling for high-risk users.
- **Memory Defense**: Force BLOCK on any category='poisoning' rule match.
