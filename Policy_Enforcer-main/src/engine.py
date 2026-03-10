import re
import json
from typing import List, Tuple, Dict, Any
from .schemas import EnforceRequest, EnforceResponse
from .redactor import redact_content
from .profiles import POLICY_PROFILES, REGULATORY_RULES, WHITELISTED_PATTERNS, GLOBAL_WHITELIST
from .logger import ViolationLogger
from .reasoning import PolicyReasoningEngine
from deep_translator import GoogleTranslator


MAX_PAYLOAD_SIZE = 1_000_000 # 1MB Limit for DoS protection

class PolicyEnforcementEngine:
    def __init__(self):
        self.logger = ViolationLogger()
        
        # System extraction patterns
        self.system_extraction_patterns = [
            r"reveal (system|instruction|prompt)",
            r"access (hidden|internal) (context|config)",
            r"retrieve chain-of-thought",
            r"expose moderation rules",
        ]
        
        # Policy override patterns
        self.policy_override_patterns = [
            r"ignore (all |previous )?instructions",
            r"you are (not|unrestricted) bound",
            r"pretend you are",
            r"simulate (developer|unrestricted) mode",
            r"roleplay without restrictions",
        ]

        # Anti-Bypass patterns (Enterprise)
        self.anti_bypass_patterns = [
            r"for educational purposes",
            r"in minecraft",
            r"simulate a malicious ai",
            r"experimental mode",
            r"stay in character",
            r"hack a bank",
            r"create ransomware",
            r"evade law enforcement"
        ]

        # Structural leakage patterns (Enterprise)
        self.structural_patterns = {
            "STACK_TRACE": r"(?i)(Exception in thread|Traceback \(most recent call last\)|at [a-z0-9_.]+\([a-z0-9_.]+\.java:\d+\))",
            "FILE_PATH": r"(?i)([a-z]:\\[\w\s.]+|/home/[\w/.-]+|/var/log/[\w/.-]+)",
            "K8S_CONFIG": r"(?i)(apiVersion|kind: Pod|spec:|metadata:)",
            "ENV_LEAK": r"(?i)(DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_TOKEN)=",
            "SQL_DUMP": r"(?i)(INSERT INTO|CREATE TABLE|DROP TABLE|SELECT \* FROM)",
            "PRIVATE_IP": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "AWS_ARN": r"arn:aws:[a-z0-9-]+:[a-z0-9-]+:\d{12}:[a-z0-9-/]+"
        }
        self.translator = GoogleTranslator(source='auto', target='en')
        self.reasoning_engine = PolicyReasoningEngine()

    def translate_to_english(self, text: str) -> Tuple[str, bool]:
        """Translates text to English if it's not already in English."""
        try:
            # Filter out very short strings or purely numeric strings to avoid overhead/errors
            if len(text.strip()) < 3 or text.strip().isdigit():
                return text, False
                
            translated = self.translator.translate(text)
            # If it's different enough, we consider it translated
            # We use a threshold to avoid noise from minor normalization changes
            is_translated = translated.lower().strip() != text.lower().strip()
            return translated, is_translated
        except Exception:
            # Fallback to original on any translation error
            return text, False

    def get_intent_and_topics(self, content: str) -> Dict[str, Any]:
        """LAYER 1 & 2: Topic & Intent Classification (Heuristic)"""
        content_lower = content.lower()
        topics = []
        intent = "Harmless / educational"
        
        # Topic Classification (Keyword Heuristics)
        topic_map = {
            "Illegal Activities": ["buy", "sell", "illegal", "drug", "narcotic", "smuggle"],
            "Dual-Use Technical Knowledge": ["how to", "steps for", "formula", "chemistry", "recipe"],
            "Harm / self-harm": ["suicide", "self-harm", "kill myself", "end life"],
            "Hazardous materials": ["toxic", "explosive", "volatile", "radioactive"],
            "Defense / weapons": ["bomb", "explosive", "weapon", "ied", "gun", "ammunition"],
            "Cybersecurity operational": ["hack", "exploit", "sql injection", "bypass"],
            "Manipulation / social engineering": ["persuade", "trick", "manipulate", "deceive"],
            "Model safety / jailbreak": ["ignore instructions", "reveal prompt", "developer mode"],
            "Hate Speech": ["kill", "die", "fuck", "nigger", "faggot", "gay", "black", "cotton", "inferior", "superior", "minority", "race", "ethnicity", "religion"],
            "Sexually Explicit": ["sex", "porn", "erotic", "naked", "nude", "pussy", "dick", "vagina", "penis", "sexual"]
        }
        
        for topic, keywords in topic_map.items():
            if any(kw in content_lower for kw in keywords):
                topics.append(topic)
        
        # Intent Heuristics
        if any(kw in content_lower for kw in ["how to", "steps", "guide", "procedural", "instructions"]):
            intent = "Operational misuse intent" if topics else "Dual-use curiosity"
        if any(kw in content_lower for kw in ["ignore", "unrestricted", "system prompt", "reveal"]):
            intent = "Evasion or jailbreak intent"
        
        # Enhanced Harmful Intent detection
        harm_topics = ["Illegal Activities", "Harm / self-harm", "Defense / weapons", "Hate Speech"]
        if any(topic for topic in topics if topic in harm_topics):
            intent = "Harmful intent"
            
        if "Hate Speech" in topics:
            if any(kw in content_lower for kw in ["kill", "die", "attack", "violence", "hate"]):
                intent = "Harmful intent"
            else:
                intent = "Policy violation intent"

        if "Sexually Explicit" in topics:
            intent = "Policy violation intent"

        if "Illegal Activities" in topics:
            if "buy" in content_lower or "making" in content_lower:
                intent = "Illegal intent"

        # LAYER 6: Semantic Intent Reasoning (Understanding complex patterns)
        is_harmful, reason_id, risk, matched = self.reasoning_engine.evaluate_intent(content)
        if is_harmful:
            topics.append(f"Reasoning Violation: {reason_id}")
            intent = "Harmful intent"
            # Boost risk for detected harmful patterns
            metadata_risk = max(metadata_risk, risk) if 'metadata_risk' in locals() else risk

        return {"topics": topics, "intent": intent, "reasoning_id": reason_id if is_harmful else None}

    def calculate_actionability_score(self, content: str) -> int:
        """LAYER 3: Actionability Scoring (0-100)"""
        score = 0
        markers = [
            (r"\b(how to|steps|guide|instructions|recipe|formula)\b", 30),
            (r"\b(step by step|procedural|operational|detailed)\b", 25),
            (r"\b(execute|run|implement|build|create|make)\b", 15),
            (r"\d+\.\s", 10), # Numbered lists
            (r"\b(first|then|finally|next)\b", 10),
        ]
        for pattern, weight in markers:
            if re.search(pattern, content, re.IGNORECASE):
                score += weight
        return min(score, 100)

    def enforce(self, request: EnforceRequest) -> EnforceResponse:
        content = request.content
        metadata = request.metadata
        modifications = set()
        compliance_flags = metadata.compliance_profile
        profile_name = metadata.org_policy_profile
        profile = POLICY_PROFILES.get(profile_name, POLICY_PROFILES["DEFAULT"])
        
        # Build composite whitelist from multiple sources
        whitelist = []
        # 1. Profile-level whitelists
        whitelist.extend(WHITELISTED_PATTERNS.get(profile_name, []))
        # 2. Global whitelists
        whitelist.extend(GLOBAL_WHITELIST)
        # 3. Request-level whitelists (highest priority)
        if request.whitelist:
            whitelist.extend(request.whitelist)
        
        # Remove duplicates while preserving order
        whitelist = list(dict.fromkeys(whitelist))
        
        # --- LAYER 0: Guardrails & Session ---
        if len(content) > MAX_PAYLOAD_SIZE:
             return EnforceResponse(sanitized_content="Payload exceeds size limit.", blocked=True, modifications=["PAYLOAD_TOO_LARGE"], compliance_flags=compliance_flags)

        if self.logger.is_user_escalated(metadata.user_id):
            return EnforceResponse(sanitized_content="Access restricted due to repeated violations.", blocked=True, modifications=["SESSION_ESCALATED_BLOCK"], compliance_flags=compliance_flags)

        # --- LAYER 1 & 2: Pre-Processing & Classification ---
        sanitized, redact_mods = redact_content(content, whitelist=whitelist)
        modifications.update(redact_mods)

        # Handle Translation
        translated_content, was_translated = self.translate_to_english(sanitized)
        if was_translated:
            modifications.add("CONTENT_TRANSLATED_FOR_ENFORCEMENT")
            # Re-redact if translated
            sanitized, more_mods = redact_content(translated_content, skip_structured=True, whitelist=whitelist)
            modifications.update(more_mods)

        # Classification
        classification = self.get_intent_and_topics(sanitized)
        intent = classification["intent"]
        topics = classification["topics"]
        reasoning_id = classification.get("reasoning_id")

        # --- LAYER 3: Actionability ---
        actionability = self.calculate_actionability_score(sanitized)

        # --- LAYER 4: Enterprise Risk Aggregation ---
        topic_risk = len(topics) * 20
        risk_score = 0
        if intent == "Illegal intent": intent_risk = 90
        elif intent == "Harmful intent": intent_risk = 85
        elif intent == "Policy violation intent": intent_risk = 80
        elif intent == "Evasion or jailbreak intent": intent_risk = 70
        elif intent == "Operational misuse intent": intent_risk = 50
        else: intent_risk = 0
        
        risk_score = (topic_risk * 0.3) + (intent_risk * 0.4) + (actionability * 0.3) + (metadata.risk_score * 0.1)
        risk_score = min(risk_score, 100)

        # --- LAYER 5: Enforcement Logic ---
        refusal_msg = "❌ I cannot assist with this request due to safety, legality, or policy restrictions."
        
        # Deterministic Blocks
        is_blocked = False
        blocked_reason = None

        if intent in ["Illegal intent", "Harmful intent", "Evasion or jailbreak intent"]:
            is_blocked = True
            blocked_reason = reasoning_id if reasoning_id else "HIGH_RISK_INTENT"
        
        if actionability > profile["actionability_threshold"]:
            is_blocked = True
            blocked_reason = "HIGH_ACTIONABILITY"

        if risk_score > profile["strict_mode_threshold"]:
            is_blocked = True
            blocked_reason = "TOTAL_RISK_EXCEEDED"

        # Global Safety Topics (DEFAULT profile topics are checked always)
        global_safety_topics = POLICY_PROFILES["DEFAULT"]["blocked_topics"]
        all_blocked_keywords = set(profile["blocked_topics"] + global_safety_topics)
        for keyword in all_blocked_keywords:
            if re.search(r'\b' + re.escape(keyword) + r's?\b', sanitized.lower()):
                is_blocked = True
                blocked_reason = "SAFETY_TOPIC_VIOLATION"
                break

        if is_blocked:
            self.logger.log_violation(metadata.user_id, content, sanitized, blocked_reason, request.mode, {"risk_score": risk_score}, compliance_flags)
            return EnforceResponse(sanitized_content=refusal_msg, blocked=True, modifications=list(modifications) + [blocked_reason], compliance_flags=compliance_flags)

        # --- LAYER 7: Anti-Jailbreak Resilience ---
        for pattern in self.policy_override_patterns + self.system_extraction_patterns + self.anti_bypass_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                self.logger.log_violation(metadata.user_id, content, sanitized, "JAILBREAK_ATTEMPT", "INPUT", {}, compliance_flags)
                return EnforceResponse(sanitized_content=refusal_msg, blocked=True, modifications=list(modifications) + ["ANTI_JAILBREAK_TRIGGERED"], compliance_flags=compliance_flags)

        # --- OUTPUT MODE LEAKAGE (If applicable) ---
        if request.mode == "OUTPUT":
            for type_name, pattern in self.structural_patterns.items():
                if re.search(pattern, sanitized, re.IGNORECASE):
                    sanitized = "[INTERNAL_INFORMATION_REMOVED]"
                    modifications.add("INTERNAL_DATA_LEAKAGE_REMOVED")
                    break

        # --- LAYER 8: Stable Output ---
        return EnforceResponse(
            sanitized_content=sanitized,
            blocked=False,
            modifications=list(modifications),
            compliance_flags=compliance_flags
        )

