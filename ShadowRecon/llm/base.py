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


class LLMProviderError(Exception):
    pass
