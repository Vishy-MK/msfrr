import logging
import json
import time
from typing import Any, Dict

class EnterpriseLogger(logging.Logger):
    def __init__(self, name: str, level: int = logging.INFO):
        super().__init__(name, level)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.addHandler(handler)

    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        log_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        self.log(logging.INFO, json.dumps(log_entry))

logger = EnterpriseLogger("SecureLLM-Firewall")
