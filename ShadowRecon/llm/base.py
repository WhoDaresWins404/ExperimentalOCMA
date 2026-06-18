import json
from abc import ABC, abstractmethod
from typing import Optional

from core.models import Finding, ScanResult


class LLMProvider(ABC):
    @abstractmethod
    async def enrich_finding(self, finding: Finding) -> Optional[Finding]:
        pass

    @abstractmethod
    async def summarize_scan(self, result: ScanResult) -> str:
        pass

    @abstractmethod
    async def generate_training_pair(self, finding: Finding) -> dict:
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        pass

    async def generate_payload(self, prompt: str, timeout: int = 120) -> str:
        return ""

    @staticmethod
    def _coerce_str_list(items: list) -> list[str]:
        """Ensure every item in a list is a string (LLM sometimes returns dicts)."""
        result = []
        for item in items:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                result.append(json.dumps(item, indent=2))
            elif isinstance(item, list):
                result.append(str(item))
            else:
                result.append(str(item) if item else "")
        return result


class LLMProviderError(Exception):
    pass
