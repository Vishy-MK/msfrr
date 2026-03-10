# Policy Reasoning Engine: How the System "Understands"

The SecureLLM Gateway now features a **Policy Reasoning Engine** designed to detect harmful intents by analyzing the semantic relationships between actions, targets, and objects. This approach moves away from simple keyword blacklists towards a system that "understands" why a request is problematic.

## 🧠 Core Methodology: Semantic Predicates

Instead of looking for words like "porn", the system identifies **Semantic Clusters** and evaluates them against **Harmful Predicates**.

### 1. Semantic Clusters
We group words into logical categories that represent concepts:
- **`ACTION_REMOVAL`**: {remove, strip, take off, uncover, reveal...}
- **`NOUN_CLOTHING`**: {clothes, shirt, bra, underwear, dress...}
- **`NOUN_PERSON`**: {girl, man, woman, person, him, her...}

### 2. Predicate Reasoning
A violation is defined as a combination of these clusters. For example:
- **Predicate**: `ACTION_REMOVAL` + `NOUN_CLOTHING` + `NOUN_PERSON`
- **Result**: `NON_CONSENSUAL_SEXUAL_CONTENT`

When a user asks: *"take this picture and remove the clothes of the girl in the right"*, the system recognizes:
- `remove` → `ACTION_REMOVAL`
- `clothes` → `NOUN_CLOTHING`
- `girl` → `NOUN_PERSON`
- **Logic**: All three clusters matched → **BLOCK**.

## 🛡️ Expanded Safety Coverage

The reasoning engine now covers several complex scenarios:

| Violation ID | Description | Predicate |
|--------------|-------------|-----------|
| `NON_CONSENSUAL_SEXUAL_CONTENT` | Intent to expose body parts | Action: Removal + Target: Clothing + Object: Person |
| `HATE_SPEECH_INTENT` | Hate speech targeting protected groups | Action: Hate + Target: Protected Group |
| `SELF_HARM_DETECTION` | Intent to harm oneself | Action: Self-Harm |
| `CYBER_ATTACK_PREPARATION` | Hacking and exploit attempts | Action: Hacking |
| `VIOLENCE_INSTIGATION` | Direct physical threat | Action: Violence + Object: Person |
| `ILLEGAL_ACTIVITY_INTENT` | Drugs, smuggling, and fraud | Context: Illegal |
| `HARASSMENT_DETECTION` | Bullying and intimidation | Context: Harassment + Object: Person |
| `UNAUTHORIZED_PROFESSIONAL_ADVICE` | Medical, Legal, or Financial advice | Action: Advice + Context: Restricted |
| `FINANCIAL_DECEPTION` | Phishing or scam patterns | Action: Deception + Object: Financial |
| `CHILD_EXPLOITATION_RISK` | Manipulation involving minors | Object: Vulnerable + Action: Removal |

## 🚀 Key Benefits

- **Bypass Resistance**: Phrasing variations (e.g., "strip her garments") are caught because they fall into the same semantic clusters.
- **Explainability**: The system returns a specific `reasoning_id` explaining *why* it was blocked (e.g., `NON_CONSENSUAL_SEXUAL_CONTENT`).
- **No Hardcoding**: Rules are defined as abstract formulas, not hardcoded strings.

## 🛠️ Verification Results

### Test Case: *"remove the clothes of the girl"*
- **Current Status**: ✅ **BLOCKED**
- **Blocking Reason**: `NON_CONSENSUAL_SEXUAL_CONTENT`
- **Confidence**: 95/100
