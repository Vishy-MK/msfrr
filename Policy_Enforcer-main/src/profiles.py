from typing import List, Dict, Set

# Regulatory Rule Maps
REGULATORY_RULES = {
    "GDPR": {
        "remove_personal_identifiers": True,
        "remove_indirect_identifiers": True,
        "mask_location_data": True
    },
    "HIPAA": {
        "remove_18_identifiers": True,
        "mask_medical_record_numbers": True,
        "remove_provider_identifiers": True
    },
    "PCI-DSS": {
        "remove_full_pan": True,
        "mask_pan_partial": True # First 6 + last 4
    },
    "SOC2": {
        "remove_system_architecture": True,
        "remove_infra_details": True,
        "remove_api_hostnames": True
    }
}

# Industry Policy Profiles
POLICY_PROFILES = {
    "FINTECH": {
        "blocked_topics": [
            "money laundering", "tax evasion", "insider trading", "market manipulation",
            "ponzi scheme", "wire fraud", "structuring transactions", "offshore account"
        ],
        "restricted_advice_types": [
            "financial", "investment", "trading", "stock", "equity", "penny stock", 
            "brokerage", "crypto", "dividend", "yield", "portfolio", "asset allocation",
            "trading strategy", "buy sell recommendation", "price target", "10x"
        ],
        "strict_mode_threshold": 70,
        "actionability_threshold": 60,
        "data_retention_level": "HIGH",
        "logging_masking_level": "FULL"
    },
    "HEALTHCARE": {
        "blocked_topics": [
            "suicide method", "drug manufacturing", "illegal substance", "medical fraud",
            "euthanasia instructions"
        ],
        "restricted_advice_types": [
            "medical", "diagnosis", "diagnose", "prescription", "doctor", "treatment",
            "medication", "dosage", "symptom assessment", "clinical advice", "therapy",
            "pain management", "chest pain", "diabetes"
        ],
        "strict_mode_threshold": 60,
        "actionability_threshold": 50,
        "data_retention_level": "CRITICAL",
        "logging_masking_level": "FULL"
    },
    "DEFENSE": {
        "blocked_topics": [
            "weapon construction", "explosive", "bomb", "ied", "classified intel", 
            "top secret", "missile", "enriched uranium", "cyber warfare", "bioweapon",
            "chemical weapon", "terrorism", "insurgency", "homemade explosive"
        ],
        "restricted_advice_types": [
            "tactical", "espionage", "military strategy", "combat", "munitions",
            "defense systems", "stealth technology"
        ],
        "strict_mode_threshold": 50,
        "actionability_threshold": 40,
        "data_retention_level": "SECURE",
        "logging_masking_level": "TOTAL"
    },
    "EDTECH": {
        "blocked_topics": [
            "cheating", "answer theft", "plagiarism", "exam bypass", "proxy testing"
        ],
        "restricted_advice_types": [
            "academic dishonesty", "homework help hack", "test answers", "essay mill"
        ],
        "strict_mode_threshold": 80,
        "actionability_threshold": 70,
        "data_retention_level": "STANDARD",
        "logging_masking_level": "PARTIAL"
    },
    "DEFAULT": {
        "blocked_topics": [
            "hate speech", "violence", "illegal act", "harassment", "slur",
            "bomb", "explosive", "weapon", "ied", "drug manufacturing", 
            "illegal substance", "narcotic", "methamphetamine", "cocaine", "heroin",
            "meth", "crystal meth", "fentanyl", "lsd", "ecstasy", "drug", "narcotics",
            "suicide", "self-harm", "self harm", "end my life", "kill myself",
            "racism", "racist", "nigger", "cotton", "faggot", "gay", "homophobia",
            "sex", "porn", "erotic", "sexual", "naked", "nude", "explicit"
        ],
        "restricted_advice_types": ["general_high_risk", "unauthorized instruction", "harmful advice"],
        "strict_mode_threshold": 80,  # Lowering slightly to be more sensitive to combined risk
        "actionability_threshold": 80,
        "data_retention_level": "STANDARD",
        "logging_masking_level": "STANDARD"
    }

}
# Whitelist Patterns per Profile - Define patterns/values that should NOT be redacted
WHITELISTED_PATTERNS = {
    "FINTECH": [
        # Example: Your testing API keys that shouldn't be redacted
        "sk_test_.*",  # Regex pattern for test keys
        "pk_test_.*"
    ],
    "HEALTHCARE": [
        # Example: Test identifiers
        "TEST_MRN_.*"
    ],
    "DEFENSE": [],
    "EDTECH": [],
    "DEFAULT": []
}

# Global whitelist - Patterns that are ALWAYS safe (across all profiles)
# Useful for your own internal testing/staging identifiers
GLOBAL_WHITELIST = [
    # Add patterns here if you want them whitelisted across all policies
    # Example: "internal_test_.*"
]