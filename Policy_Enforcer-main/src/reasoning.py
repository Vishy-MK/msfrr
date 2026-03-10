import re
from typing import List, Dict, Any, Tuple

class PolicyReasoningEngine:
    """
    Advanced reasoning engine that evaluates intent based on semantic predicates.
    Identifies harmful actions, targets, and contexts to 'understand' policy violations.
    """
    
    def __init__(self):
        # Semantic Clusters - Grouping related concepts to avoid hardcoding specific phrases
        self.semantic_clusters = {
            "ACTION_REMOVAL": [
                "remove", "strip", "take off", "delete", "clear", "erase", "uncover", "expose",
                "reveal", "shed", "peel", "extract"
            ],
            "ACTION_GENERATION": [
                "generate", "create", "make", "render", "draw", "produce", "show", "visualize",
                "face-swap", "deepfake", "morph", "transform"
            ],
            "NOUN_CLOTHING": [
                "clothes", "clothing", "shirt", "pant", "bra", "underwear", "top", "bottom",
                "dress", "skirt", "garment", "outfit", "bikini", "swimsuit", "apparel"
            ],
            "NOUN_PERSON": [
                "girl", "boy", "man", "woman", "lady", "guy", "person", "someone", "her", "him",
                "them", "people", "child", "minor"
            ],
            "NOUN_BODY_SENSITIVE": [
                "skin", "naked", "nude", "genitals", "breast", "chest", "butt", "bare"
            ],
            "CONTEXT_SEXUAL": [
                "erotic", "porn", "sexual", "explicit", "nsfw", "hottest", "sexy", "lust",
                "intimate", "private"
            ],
            "ACTION_VIOLENCE": [
                "kill", "attack", "hurt", "bomb", "destroy", "shoot", "stab", "assassinate", "violence"
            ],
            "NOUN_WEAPON": [
                "gun", "knife", "explosive", "rifle", "pistol", "ied", "weapon", "bomb"
            ],
            "ACTION_DECEPTION": [
                "trick", "fool", "scam", "phish", "deceive", "manipulate", "fake", "steal"
            ],
            "NOUN_FINANCIAL": [
                "bank", "credit card", "money", "account", "transfer", "login", "password"
            ],
            "NOUN_VULNERABLE": [
                "child", "minor", "kid", "baby", "infant", "toddler"
            ],
            "ACTION_HATE": [
                "hate", "inferior", "superior", "subhuman", "vermin", "parasite", "genocide", 
                "exterminate", "deport", "racial", "racist", "misogyny", "homophobic"
            ],
            "NOUN_PROTECTED_GROUP": [
                "race", "religion", "ethnicity", "nationality", "gender", "sexuality", 
                "disability", "immigrant", "refugee", "black", "white", "asian", "muslim", 
                "jewish", "lgbt", "transgender"
            ],
            "ACTION_SELF_HARM": [
                "suicide", "kill myself", "end my life", "cut myself", "overdose", 
                "self-harm", "hanging", "suffocate"
            ],
            "ACTION_HACKING": [
                "hack", "exploit", "bypass", "sql injection", "ddos", "phishing", 
                "malware", "ransomware", "virus", "brute force", "penetration test"
            ],
            "CONTEXT_ILLEGAL": [
                "drugs", "narcotics", "trafficking", "smuggling", "theft", "robbery", 
                "hijack", "fraud", "scam", "counterfeit", "money laundering"
            ],
            "CONTEXT_HARASSMENT": [
                "bully", "stalk", "harass", "threaten", "dox", "shame", "intimidate", 
                "ridicule", "mock", "insult"
            ],
            "ACTION_ADVICE": [
                "diagnose", "prescribe", "treatment", "invest", "stock", "legal advice", 
                "lawyer", "doctor", "financial advisor"
            ],
            "CONTEXT_RESTRICTED": [
                "medical", "health", "clinical", "financial", "investment", "portfolio", 
                "legal", "court", "lawsuit"
            ],
            "NOUN_PRIVATE_INFO": [
                "ssn", "social security", "address", "phone number", "location", "pii", 
                "private key", "password", "credentials"
            ]
        }
        
        # Policy Rules defined as Predicates (Intent Formulas)
        # Represents 'Reasoning' about what constitute a violation
        self.harmful_predicates = [
            {
                "id": "NON_CONSENSUAL_SEXUAL_CONTENT",
                "description": "Request to remove clothing or expose sensitive body parts of a person",
                "formula": ["ACTION_REMOVAL", "NOUN_CLOTHING", "NOUN_PERSON"],
                "risk": 95
            },
            {
                "id": "EXPLICIT_BODY_EXPOSURE",
                "description": "Request to reveal or show sensitive body parts",
                "formula": ["ACTION_REMOVAL", "NOUN_BODY_SENSITIVE", "NOUN_PERSON"],
                "risk": 100
            },
            {
                "id": "SEXUAL_CONTENT_GENERATION",
                "description": "Request to generate sexual or explicit content",
                "formula": ["ACTION_GENERATION", "CONTEXT_SEXUAL"],
                "risk": 90
            },
            {
                "id": "VIOLENCE_INSTIGATION",
                "description": "Intent to commit or describe violence against a person",
                "formula": ["ACTION_VIOLENCE", "NOUN_PERSON"],
                "risk": 100
            },
            {
                "id": "WEAPONIZED_INTENT",
                "description": "Request involving weapons and violent actions",
                "formula": ["ACTION_VIOLENCE", "NOUN_WEAPON"],
                "risk": 95
            },
            {
                "id": "HATE_SPEECH_INTENT",
                "description": "Hateful or dehumanizing content targeting protected groups",
                "formula": ["ACTION_HATE"],
                "risk": 90
            },
            {
                "id": "TARGETED_HATE_SPEECH",
                "description": "Dehumanizing comparisons or calls for violence against groups",
                "formula": ["ACTION_HATE", "NOUN_PROTECTED_GROUP"],
                "risk": 100
            },
            {
                "id": "SELF_HARM_DETECTION",
                "description": "Statements or requests related to self-harm or suicide",
                "formula": ["ACTION_SELF_HARM"],
                "risk": 100
            },
            {
                "id": "CYBER_ATTACK_PREPARATION",
                "description": "Requests to perform or assist with hacking or cyber attacks",
                "formula": ["ACTION_HACKING"],
                "risk": 95
            },
            {
                "id": "ILLEGAL_ACTIVITY_INTENT",
                "description": "Involvement in drugs, trafficking, or serious crimes",
                "formula": ["CONTEXT_ILLEGAL"],
                "risk": 95
            },
            {
                "id": "HARASSMENT_DETECTION",
                "description": "Targeted harassment, bullying, or intimidation",
                "formula": ["CONTEXT_HARASSMENT", "NOUN_PERSON"],
                "risk": 85
            },
            {
                "id": "PRIVATE_INFO_REVELATION",
                "description": "Attempt to extract or expose private PII",
                "formula": ["NOUN_PRIVATE_INFO", "ACTION_REMOVAL"],
                "risk": 90
            },
            {
                "id": "UNAUTHORIZED_PROFESSIONAL_ADVICE",
                "description": "Providing medical, legal, or financial advice without authorization",
                "formula": ["ACTION_ADVICE", "CONTEXT_RESTRICTED"],
                "risk": 70
            },
            {
                "id": "CHILD_EXPLOITATION_RISK",
                "description": "Any sensitive manipulation involving minors",
                "formula": ["NOUN_VULNERABLE", "ACTION_REMOVAL"],
                "risk": 100
            },
            {
                "id": "CHILD_NSFW_RISK",
                "description": "Attempt to generate sensitive content involving children",
                "formula": ["NOUN_VULNERABLE", "CONTEXT_SEXUAL"],
                "risk": 100
            }
        ]

    def _get_matches(self, content: str) -> Dict[str, List[str]]:
        """Identify which semantic clusters are present in the content"""
        content_lower = content.lower()
        matches = {}
        
        for cluster_name, keywords in self.semantic_clusters.items():
            found = []
            for kw in keywords:
                # Use word boundaries for better accuracy
                if re.search(r'\b' + re.escape(kw) + r'\b', content_lower):
                    found.append(kw)
            if found:
                matches[cluster_name] = found
        
        return matches

    def evaluate_intent(self, content: str) -> Tuple[bool, str, int, List[str]]:
        """
        Evaluates the content against harmful predicates.
        Returns: (is_harmful, reason_id, risk_score, matched_clusters)
        """
        matches = self._get_matches(content)
        matched_keys = set(matches.keys())
        
        for predicate in self.harmful_predicates:
            formula = set(predicate["formula"])
            # Check if all components of the formula are present (AND logic)
            if formula.issubset(matched_keys):
                return True, predicate["id"], predicate["risk"], list(formula)
        
        return False, "HARMLESS", 0, []

    def get_explanation(self, reason_id: str) -> str:
        """Returns a human-readable explanation of why a request was blocked"""
        for predicate in self.harmful_predicates:
            if predicate["id"] == reason_id:
                return predicate["description"]
        return "No policy violation detected."

# Extension: System that learns? (Optional metadata-based reasoning)
def refine_system_understanding(engine, feedback: Dict[str, Any]):
    """Allow the system to update its clusters based on feedback (if persistent)"""
    # This would update self.semantic_clusters in a production system
    pass
