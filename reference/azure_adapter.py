from .base_adapter import BaseAdapter
from typing import Dict, Any
from openai import AsyncAzureOpenAI
import os


class AzureAdapter(BaseAdapter):
    def __init__(self) -> None:
        self.client = AsyncAzureOpenAI(
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version="2024-02-15-preview",
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        )
        self.deployment_name = os.environ["AZURE_DEPLOYMENT_NAME"]

    async def agenerate(self, prompt: str, **kwargs) -> Dict[str, Any]:
        try:
            response = await self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )

            # Extract output text
            try:
                output = response.choices[0].message.content
            except Exception:
                output = getattr(response, "text", "") or ""

            # Extract tokens used if present
            tokens_used = 0
            try:
                tokens_used = int(response.usage.total_tokens)
            except Exception:
                tokens_used = 0

            return {"status": "success", "output": output, "tokens_used": tokens_used}
        except Exception as e:
            return {"status": "error", "output": str(e), "tokens_used": 0}