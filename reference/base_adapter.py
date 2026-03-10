# adapters/base_adapter.py
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseAdapter(ABC):
    @abstractmethod
    async def agenerate(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """
        Must return:
        - status: 'success' or 'error'
        - output: Raw text response
        - tokens_used: Integer
        """
        pass