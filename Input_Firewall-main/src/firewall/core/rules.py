import re
import yaml
from typing import List, Dict, Any
from pathlib import Path

class RuleEngine:
    def __init__(self, rules_path: str):
        self.rules = self._load_rules(rules_path)
        self.compiled_rules = self._compile_rules()

    def _load_rules(self, path: str) -> List[Dict[str, Any]]:
        if not Path(path).exists():
            return []
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('rules', [])

    def _compile_rules(self):
        compiled = []
        for rule in self.rules:
            try:
                compiled.append({
                    **rule,
                    "prog": re.compile(rule['pattern'])
                })
            except Exception as e:
                # Log error in rule compilation but don't stop the whole engine
                pass
        return compiled

    def evaluate(self, text: str) -> List[Dict[str, Any]]:
        """
        Evaluate text against all rules. Returns a list of matched rules.
        """
        matches = []
        for rule in self.compiled_rules:
            if rule['prog'].search(text):
                matches.append({
                    **{k: v for k, v in rule.items() if k != 'prog'}
                })
        return matches
