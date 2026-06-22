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
                "auto_verify": True,
            }


async def _chain_rxss_to_cookie_theft(finding: Finding, tech: dict):
    if "xss" in finding.title.lower() or "reflected" in finding.tags:
        finding._chain_hint = {
            "scanner": "reflection_injector",
            "reason": "Reflected XSS confirmed — cookie theft / phishing simulation possible",
            "priority": "medium",
            "auto_verify": True,
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
                "auto_verify": True,
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
            "auto_verify": True,
        }


async def _chain_api_key_in_js(finding: Finding, tech: dict):
    if "api key" in finding.title.lower() or "secret" in finding.title.lower():
        evidence = finding.evidence or {}
        if "url" in evidence:
            finding._chain_hint = {
                "scanner": "api_fuzzer",
                "payload_source": evidence["url"],
                "reason": "API key/secret found in JS — amplify API fuzzing on this origin",
                "priority": "high",
                "auto_verify": True,
            }


async def _chain_debug_endpoint_to_xst(finding: Finding, tech: dict):
    if "debug" in finding.title.lower() or "stack trace" in finding.title.lower():
        finding._chain_hint = {
            "scanner": "misconfig_scanner",
            "reason": "Debug endpoint exposed — enable XST (X-Requested-With) testing",
            "priority": "medium",
            "auto_verify": True,
        }


async def _chain_env_exposure_to_secrets(finding: Finding, tech: dict):
    if ".env" in finding.title.lower() or "environment" in finding.title.lower():
        evidence = finding.evidence or {}
        if "url" in evidence and ".env" in str(evidence.get("url", "")):
            finding._chain_hint = {
                "scanner": "directory_scanner",
                "augmented_wordlist": [
                    ".env.local", ".env.production", ".env.development",
                    ".env.backup", ".env.old", "env.txt",
                ],
                "reason": ".env file exposed — probing for more environment files",
                "priority": "critical",
                "auto_verify": True,
            }


async def _chain_sqli_to_deep_exploit(finding: Finding, tech: dict):
    if "sqli" in finding.tags or "sql injection" in finding.title.lower():
        finding._chain_hint = {
            "scanner": "sqli_scanner",
            "reason": "SQL injection confirmed — running deeper time-based and UNION probes",
            "priority": "critical",
            "auto_verify": True,
        }


async def _chain_lfi_to_rce(finding: Finding, tech: dict):
    if "lfi" in finding.tags or "file inclusion" in finding.title.lower():
        evidence = finding.evidence or {}
        if "url" in evidence:
            finding._chain_hint = {
                "scanner": "lfi_scanner",
                "reason": "LFI confirmed — attempting log poisoning / php://input for RCE",
                "priority": "critical",
                "auto_verify": True,
            }


async def _chain_idor_to_privilege_escalation(finding: Finding, tech: dict):
    if "idor" in finding.tags or "insecure direct" in finding.title.lower():
        finding._chain_hint = {
            "scanner": "idor_scanner",
            "reason": "IDOR found — escalating to privilege escalation / mass enumeration",
            "priority": "high",
            "auto_verify": True,
        }


def build_chaining_engine() -> ChainingEngine:
    engine = ChainingEngine()
    engine.on_finding(_chain_open_redirect_to_ssrf)
    engine.on_finding(_chain_rxss_to_cookie_theft)
    engine.on_finding(_chain_git_exposure)
    engine.on_finding(_chain_ssrf_to_metadata)
    engine.on_finding(_chain_api_key_in_js)
    engine.on_finding(_chain_debug_endpoint_to_xst)
    engine.on_finding(_chain_env_exposure_to_secrets)
    engine.on_finding(_chain_sqli_to_deep_exploit)
    engine.on_finding(_chain_lfi_to_rce)
    engine.on_finding(_chain_idor_to_privilege_escalation)
    return engine
