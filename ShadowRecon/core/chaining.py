from typing import Callable, Awaitable

from core.models import Finding, FindingSeverity


ChainHook = Callable[[Finding, dict], Awaitable[None]]


class ChainingEngine:
    def __init__(self):
        self._hooks: dict[str, list[ChainHook]] = {
            "finding_added": [],
        }

    def on_finding(self, hook: ChainHook):
        self._hooks["finding_added"].append(hook)

    async def absorb(self, finding: Finding, tech: dict | None = None):
        for hook in self._hooks["finding_added"]:
            try:
                await hook(finding, tech or {})
            except Exception:
                pass


async def _chain_open_redirect_to_ssrf(finding: Finding, tech: dict):
    if "open redirect" in finding.title.lower() or "redirect" in finding.tags:
        evidence = finding.evidence or {}
        if "url" in evidence:
            finding._chain_hint = {
                "scanner": "ssrf_scanner",
                "payload_source": evidence["url"],
                "reason": "Open redirect found — SSRF via redirect chaining possible",
                "priority": "high",
            }


async def _chain_rxss_to_cookie_theft(finding: Finding, tech: dict):
    if "xss" in finding.title.lower() or "reflected" in finding.tags:
        finding._chain_hint = {
            "scanner": "reflection_injector",
            "reason": "Reflected XSS confirmed — cookie theft / phishing simulation possible",
            "priority": "medium",
        }


async def _chain_git_exposure(finding: Finding, tech: dict):
    if ".git" in finding.title.lower() or finding.severity == FindingSeverity.CRITICAL:
        evidence = finding.evidence or {}
        if "url" in evidence and ".git" in str(evidence.get("url", "")):
            finding._chain_hint = {
                "scanner": "directory_scanner",
                "augmented_wordlist": [
                    ".git/config", ".git/HEAD", ".git/index",
                    ".git/objects/", ".git/logs/",
                ],
                "reason": ".git exposure — deeper git enumeration queued",
                "priority": "high",
            }


async def _chain_ssrf_to_metadata(finding: Finding, tech: dict):
    if "ssrf" in finding.tags:
        finding._chain_hint = {
            "scanner": "ssrf_scanner",
            "extra_payloads": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
            "reason": "SSRF confirmed — AWS metadata extraction queued",
            "priority": "critical",
        }


def build_chaining_engine() -> ChainingEngine:
    engine = ChainingEngine()
    engine.on_finding(_chain_open_redirect_to_ssrf)
    engine.on_finding(_chain_rxss_to_cookie_theft)
    engine.on_finding(_chain_git_exposure)
    engine.on_finding(_chain_ssrf_to_metadata)
    return engine
