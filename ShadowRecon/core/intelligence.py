import re
from typing import Optional, Callable, Any

from .models import (
    TechFingerprint, Directive, ScanStrategy, ScanProfile,
    Finding, Endpoint, FindingSeverity
)
from .directive import DirectiveBus
from .config import ScanConfig


class IntelRule:
    """A rule that matches findings/endpoints and produces directives."""

    def __init__(
        self,
        match_fn: Callable[[Finding, str], bool],
        directives_fn: Callable[[Finding, str], list[Directive]],
        description: str = "",
    ):
        self.match = match_fn
        self.directives = directives_fn
        self.description = description


# ── Built-in escalation rules ─────────────────────────────────────

def _is_high_sev(finding: Finding, scanner_name: str) -> bool:
    return finding.severity.value in ("high", "critical")


def _escalate_on_high_sev(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("anomaly_detector", "adjust_param",
                  {"depth": 2}, "High-severity finding — increase anomaly depth",
                  priority=1),
    ]


def _is_git_exposed(finding: Finding, scanner_name: str) -> bool:
    return "git" in finding.title.lower() or ".git" in str(finding.evidence)


def _probe_git_deeper(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("directory_scanner", "augment_wordlist",
                  ["/.git/config", "/.git/HEAD", "/.git/refs/", "/.git/logs/",
                   "/.gitignore", "/.gitattributes"],
                  ".git repo exposed — probe deeper", priority=2),
    ]


def _is_admin_panel(finding: Finding, scanner_name: str) -> bool:
    return "admin" in finding.title.lower() and scanner_name == "directory_scanner"


def _probe_admin_deeper(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("crawler_scanner", "prioritize_path",
                  {"prefix": finding.endpoint_id or ""},
                  "Admin panel found — crawl deeper", priority=2),
        Directive("misconfig_scanner", "enable_check",
                  "check_auth_bypass", "Admin panel — check auth", priority=1),
    ]


def _is_cors_misconfig(finding: Finding, scanner_name: str) -> bool:
    return "cors" in finding.title.lower() and scanner_name == "misconfig_scanner"


def _escalate_on_cors(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("api_scanner", "augment_wordlist",
                  ["/api/user", "/api/admin", "/api/internal"],
                  "CORS misconfig — probe API endpoints", priority=1),
    ]


BUILTIN_RULES = [
    IntelRule(_is_high_sev, _escalate_on_high_sev, "Escalate on high/critical finding"),
    IntelRule(_is_git_exposed, _probe_git_deeper, "Probe .git deeper when found"),
    IntelRule(_is_admin_panel, _probe_admin_deeper, "Deep crawl admin panels"),
    IntelRule(_is_cors_misconfig, _escalate_on_cors, "Probe APIs when CORS is misconfigured"),
]


class IntelligenceCore:
    """Central feedback hub — ingests findings/endpoints mid-scan and issues directives."""

    def __init__(
        self,
        directive_bus: DirectiveBus,
        config: ScanConfig,
        rules: Optional[list[IntelRule]] = None,
    ):
        self.bus = directive_bus
        self.config = config
        self.rules = rules or BUILTIN_RULES
        self.profile: Optional[ScanProfile] = None
        self._finding_count = 0
        self._endpoint_count = 0

    async def set_profile(self, fp: TechFingerprint, llm_strategy: Optional[ScanStrategy] = None):
        """Phase 1: Build ScanProfile from fingerprint + optional LLM strategy."""
        self.profile = ScanProfile.from_fingerprint(fp, llm_strategy)
        dirs = self.profile.to_directives()
        if dirs:
            await self.bus.issue_many(dirs)

    async def apply_strategy(self, strategy: ScanStrategy):
        """Apply LLM-generated strategy directives."""
        for sn in strategy.skip_scanners:
            await self.bus.issue(Directive(sn, "skip", None, strategy.rationale, priority=2))
        for sn in strategy.priority_scanners:
            await self.bus.issue(Directive(sn, "adjust_param",
                                 {"priority_boost": True}, "LLM priority", priority=2))
        for sn, paths in strategy.augmented_wordlists.items():
            await self.bus.issue(Directive(sn, "augment_wordlist", paths,
                                 strategy.rationale, priority=2))

    async def absorb_finding(self, finding: Finding, scanner_name: str):
        """Ingest a finding mid-scan and evaluate escalation rules."""
        self._finding_count += 1
        if not self.config.intelligence.enabled:
            return
        for rule in self.rules:
            try:
                if rule.match(finding, scanner_name):
                    dirs = rule.directives(finding, scanner_name)
                    if dirs:
                        await self.bus.issue_many(dirs)
            except Exception:
                pass

    async def absorb_endpoint(self, endpoint: Endpoint, scanner_name: str):
        """Ingest an endpoint mid-scan (for future use)."""
        self._endpoint_count += 1

    @property
    def stats(self) -> dict:
        return {
            "findings_absorbed": self._finding_count,
            "endpoints_absorbed": self._endpoint_count,
            "active_directives": 0,  # filled in after call
        }
