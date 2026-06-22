import re
from typing import Optional, Callable, Any

from .models import (
    TechFingerprint, Directive, ScanStrategy, ScanProfile,
    Finding, Endpoint, FindingSeverity
)
from .directive import DirectiveBus
from .config import ScanConfig


class IntelRule:
    def __init__(
        self,
        match_fn: Callable[[Finding, str], bool],
        directives_fn: Callable[[Finding, str], list[Directive]],
        description: str = "",
    ):
        self.match = match_fn
        self.directives = directives_fn
        self.description = description


# ── Original rules ─────────────────────────────────────────────────

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

# ── New escalation rules ───────────────────────────────────────────

def _is_api_key_in_js(finding: Finding, scanner_name: str) -> bool:
    return ("api key" in finding.title.lower() or "secret" in finding.title.lower()) and scanner_name in ("js_analyzer", "recon_scanner")

def _escalate_api_key_in_js(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("api_fuzzer", "augment_wordlist",
                  ["/api/v2", "/api/v3", "/internal/api", "/api/private"],
                  "API key found in JS — amplify API fuzzing", priority=2),
        Directive("js_analyzer", "adjust_param",
                  {"scan_depth": "deep"}, "API key found — deep JS scan", priority=1),
    ]

def _is_env_exposed(finding: Finding, scanner_name: str) -> bool:
    return ".env" in finding.title.lower() and scanner_name == "directory_scanner"

def _escalate_env_exposed(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("directory_scanner", "augment_wordlist",
                  [".env.local", ".env.production", ".env.backup", "env.txt",
                   ".env.dist", ".env.staging", "environment.yml"],
                  ".env exposed — probe for more environment files", priority=2),
        Directive("misconfig_scanner", "enable_check",
                  "check_debug", "Exposed .env — enable debug checks", priority=1),
    ]

def _is_debug_endpoint(finding: Finding, scanner_name: str) -> bool:
    return ("debug" in finding.title.lower() or "stack trace" in finding.title.lower() or "phpinfo" in finding.title.lower())

def _escalate_debug_endpoint(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("directory_scanner", "augment_wordlist",
                  ["/debug", "/debug/", "/api/debug", "/api/status",
                   "/console", "/whoami", "/phpinfo.php", "/info.php"],
                  "Debug endpoint found — probe debug paths", priority=2),
    ]

def _is_ssrf_finding(finding: Finding, scanner_name: str) -> bool:
    return "ssrf" in finding.tags

def _escalate_ssrf(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("ssrf_scanner", "augment_wordlist",
                  ["http://169.254.169.254/latest/meta-data/",
                   "http://169.254.169.254/latest/user-data/",
                   "http://metadata.google.internal/",
                   "http://100.100.100.200/latest/meta-data/",
                   "http://localhost:9001/"],
                  "SSRF confirmed — probe cloud metadata endpoints", priority=2),
    ]

def _is_jwt_finding(finding: Finding, scanner_name: str) -> bool:
    return "jwt" in finding.tags or "jwt" in finding.title.lower()

def _escalate_jwt(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("jwt_scanner", "adjust_param",
                  {"test_kid_injection": True, "test_jku": True, "test_sub": True},
                  "JWT issue found — run advanced KID/JKU/sub attacks", priority=2),
    ]

def _is_ssti_finding(finding: Finding, scanner_name: str) -> bool:
    return "ssti" in finding.tags or "template" in finding.title.lower()

def _escalate_ssti(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("ssti_scanner", "adjust_param",
                  {"depth": "rce", "test_blind": True},
                  "SSTI confirmed — escalate to RCE probes", priority=2),
    ]

def _is_xss_finding(finding: Finding, scanner_name: str) -> bool:
    return "xss" in finding.tags

def _escalate_xss(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("blind_xss_scanner", "enable_check",
                  "enabled", "XSS found — enable Blind XSS probes via stored vectors", priority=2),
    ]

def _is_nosqli_finding(finding: Finding, scanner_name: str) -> bool:
    return "nosqli" in finding.tags

def _escalate_nosqli(finding: Finding, scanner_name: str) -> list[Directive]:
    return [
        Directive("nosqli_scanner", "adjust_param",
                  {"depth": "deep", "test_timebased": True},
                  "NoSQLi found — run deep timing-based probes", priority=2),
    ]


BUILTIN_RULES = [
    IntelRule(_is_high_sev, _escalate_on_high_sev, "Escalate on high/critical finding"),
    IntelRule(_is_git_exposed, _probe_git_deeper, "Probe .git deeper when found"),
    IntelRule(_is_admin_panel, _probe_admin_deeper, "Deep crawl admin panels"),
    IntelRule(_is_cors_misconfig, _escalate_on_cors, "Probe APIs when CORS is misconfigured"),
    IntelRule(_is_api_key_in_js, _escalate_api_key_in_js, "Amplify API fuzzing when API keys found"),
    IntelRule(_is_env_exposed, _escalate_env_exposed, "Probe env files deeper"),
    IntelRule(_is_debug_endpoint, _escalate_debug_endpoint, "Probe debug paths"),
    IntelRule(_is_ssrf_finding, _escalate_ssrf, "Cloud metadata enumeration on SSRF"),
    IntelRule(_is_jwt_finding, _escalate_jwt, "Advanced JWT attacks on JWT finding"),
    IntelRule(_is_ssti_finding, _escalate_ssti, "SSTI RCE escalation"),
    IntelRule(_is_xss_finding, _escalate_xss, "Enable Blind XSS on XSS finding"),
    IntelRule(_is_nosqli_finding, _escalate_nosqli, "Deep NoSQL injection probes"),
]


class IntelligenceCore:
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
        self.profile = ScanProfile.from_fingerprint(fp, llm_strategy)
        dirs = self.profile.to_directives()
        if dirs:
            await self.bus.issue_many(dirs)

    async def apply_strategy(self, strategy: ScanStrategy):
        for sn in strategy.skip_scanners:
            await self.bus.issue(Directive(sn, "skip", None, strategy.rationale, priority=2))
        for sn in strategy.priority_scanners:
            await self.bus.issue(Directive(sn, "adjust_param",
                                 {"priority_boost": True}, "LLM priority", priority=2))
        for sn, paths in strategy.augmented_wordlists.items():
            await self.bus.issue(Directive(sn, "augment_wordlist", paths,
                                 strategy.rationale, priority=2))

    async def absorb_finding(self, finding: Finding, scanner_name: str):
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
        self._endpoint_count += 1

    @property
    def stats(self) -> dict:
        return {
            "findings_absorbed": self._finding_count,
            "endpoints_absorbed": self._endpoint_count,
            "active_directives": 0,
        }
