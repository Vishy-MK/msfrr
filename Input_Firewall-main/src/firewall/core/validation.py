from typing import Dict, Any
import json

class StructuralValidator:
    def __init__(self, max_prompt_length: int = 10000):
        self.max_prompt_length = max_prompt_length

    def validate(self, prompt: str, model_config: Dict[str, Any] = None) -> bool:
        """
        Ensure the prompt and config meet enterprise structural requirements.
        """
        # 1. Size Check
        if len(prompt) > self.max_prompt_length:
            return False

        # 2. JSON Integrity (if applicable)
        # Check if the prompt is trying to break out of a JSON structure
        # A common injection is "}, {"system": "..."}"
        if model_config:
            try:
                # Validate model_config doesn't contain suspicious overrides
                config_str = json.dumps(model_config)
                if "system" in config_str.lower() or "instruction" in config_str.lower():
                    # Enterprise policy: users cannot override system instructions via model_config
                    return False
            except (TypeError, ValueError):
                return False

        return True
