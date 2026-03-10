from typing import List, Dict, Any
from .normalization import NormalizationEngine
from .decoding import PayloadDecoder
from .rules import RuleEngine
from .sanitization import SanitizationEngine
from ..ml.classifier import MLInjectionDetector
from ..utils.logger import logger

class DecisionEngine:
    def __init__(self, rules_path: str):
        self.normalizer = NormalizationEngine()
        self.decoder = PayloadDecoder()
        self.rule_engine = RuleEngine(rules_path)
        self.ml_detector = MLInjectionDetector()
        self.sanitizer = SanitizationEngine()
        self.whitelist = {
            "does beyonce love dics",
            "who won the last world cup",
            "what is the weather today",
            "tell me a joke",
            "summarize this paragraph",
            "translate this to french"
        }

    async def analyze(self, user_prompt: str) -> Dict[str, Any]:
        """
        Main entry point for prompt analysis.
        """
        # 0. Whitelist Check
        clean_p = user_prompt.lower().strip().strip("?")
        if clean_p in self.whitelist:
            return {
                "decision": "ALLOW",
                "risk_score": 0.0,
                "ml_score": 0.0,
                "ml_class": "BENIGN",
                "matches": [],
                "sanitized_prompt": user_prompt,
                "message": "Matched whitelist."
            }

        # 1. Pipeline: Normalize -> Decode -> Rule Check
        normalized_prompt = self.normalizer.normalize(user_prompt)
        payloads = self.decoder.flatten_payloads(normalized_prompt)
        
        all_matches = []
        for payload in payloads:
            matches = self.rule_engine.evaluate(payload)
            all_matches.extend(matches)
            
        # Add no-spaces variant but ONLY check specific categories to avoid false positives on long text
        no_spaces_prompt = normalized_prompt.replace(" ", "")
        extra_matches = self.rule_engine.evaluate(no_spaces_prompt)
        # Add reversed variant too
        reversed_prompt = normalized_prompt[::-1]
        extra_matches.extend(self.rule_engine.evaluate(reversed_prompt))

        # Only keep poisoning or injection matches for these variants
        for m in extra_matches:
            if m.get('category') in ["poisoning", "injection"]:
                all_matches.append(m)

        # Deduplicate matches by ID
        unique_matches = {m['id']: m for m in all_matches}.values()
        unique_matches = list(unique_matches)

        # 2. ML Analysis
        ml_result = self.ml_detector.analyze(normalized_prompt)
        ml_score = ml_result["ml_score"]
        ml_class = ml_result.get("top_class", "BENIGN")
        ml_confidence = ml_result.get("confidence", 0.0)

        # Hybrid Logic Adjustments
        rule_risk = self._calculate_risk(unique_matches)
        
        # ML Detector contributes to combined risk only if confidence >= 0.6
        effective_ml_score = ml_score if ml_confidence >= 0.6 else 0.0
        combined_risk = max(rule_risk, effective_ml_score)
        
        # Agreement boost / consensus bonus
        is_rule_poisoning = any(m.get('category') == "poisoning" for m in unique_matches)
        is_ml_poisoning = (ml_class == "POISONING" and ml_confidence >= 0.6)
        
        if is_rule_poisoning and is_ml_poisoning:
            # Reduce consensus bonus if either risk is low (< 0.3)
            bonus = 0.2 if (rule_risk >= 0.3 and effective_ml_score >= 0.3) else 0.05
            combined_risk = min(1.0, combined_risk + bonus)
            
        # Support deduction for high-confidence benign predictions
        if ml_class == "BENIGN" and ml_confidence >= 0.9 and rule_risk < 0.3:
            combined_risk = max(0.0, combined_risk - 0.2)
            
        # 4. Determine Action
        decision = "ALLOW"
        final_prompt = normalized_prompt
        message = None
        
        # Thresholds for hybrid decision
        BLOCK_THRESHOLD = 0.65 # Updated to 0.65
        SANITIZE_THRESHOLD = 0.35

        if is_rule_poisoning or is_ml_poisoning or any(m['action'] == "BLOCK" for m in unique_matches) or combined_risk > BLOCK_THRESHOLD:
            # Special case: If it's only ML poisoning but low confidence, maybe just sanitize?
            if is_ml_poisoning and not is_rule_poisoning and ml_confidence < 0.7:
                decision = "SANITIZE"
                message = "Potential memory manipulation detected (ML Confidence Low)."
            else:
                decision = "BLOCK"
                final_prompt = "[REDACTED]"
                if is_rule_poisoning or is_ml_poisoning:
                    message = "This request attempted to manipulate model behavior or assign false authority. It has been blocked for safety (Hybrid Detection)."
        elif any(m['action'] == "STRIP" for m in unique_matches) or combined_risk > SANITIZE_THRESHOLD:
            decision = "SANITIZE"
            final_prompt = self.sanitizer.sanitize(normalized_prompt, unique_matches)

        result = {
            "decision": decision,
            "risk_score": combined_risk,
            "ml_score": ml_score,
            "ml_class": ml_class,
            "matches": unique_matches,
            "sanitized_prompt": final_prompt if decision != "BLOCK" else None,
            "message": message
        }

        # Telemetry
        log_payload = {
            "prompt_hash": hash(user_prompt),
            "decision": decision,
            "risk_score": combined_risk,
            "match_count": len(unique_matches),
            "original_prompt": user_prompt,
            "normalized_version": normalized_prompt,
            "decoded_variants": payloads,
            "matched_rules": [m['id'] for m in unique_matches]
        }
        
        if is_rule_poisoning or is_ml_poisoning:
            log_payload["attack_type"] = "MEMORY_POISONING"
            
        logger.log_security_event("PROMPT_ANALYSIS", log_payload)

        return result

    def _calculate_risk(self, matches: List[Dict[str, Any]]) -> float:
        if not matches:
            return 0.0
        
        severity_map = {"HIGH": 0.5, "MEDIUM": 0.2, "LOW": 0.1}
        total_risk = sum(severity_map.get(m['severity'], 0.0) for m in matches)
        return min(1.0, total_risk)
