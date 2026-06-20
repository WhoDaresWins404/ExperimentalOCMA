import fnmatch
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class ScopeRule:
    pattern: str
    is_included: bool = True
    note: str = ""

    def matches(self, url: str) -> bool:
        hostname = urlparse(url).hostname or ""
        return fnmatch.fnmatch(hostname, self.pattern)


@dataclass
class ScopeConfig:
    in_scope: list[ScopeRule] = field(default_factory=list)
    out_of_scope: list[ScopeRule] = field(default_factory=list)
    cdn_domains: set[str] = field(default_factory=lambda: {
        "cloudflare.net", "cloudflare.com",
        "akamaiedge.net", "akamaiedge-staging.net",
        "fastly.net", "fastlylb.net",
        "amazonaws.com", "cloudfront.net",
        "azureedge.net", "azurefd.net",
        "cdn.cloudflare.net",
    })

    def is_in_scope(self, url: str) -> bool:
        hostname = urlparse(url).hostname or ""
        for rule in self.out_of_scope:
            if rule.matches(hostname):
                return False
        for rule in self.in_scope:
            if rule.matches(hostname):
                return True
        return False

    def is_cdn(self, url: str) -> bool:
        hostname = urlparse(url).hostname or ""
        return any(d in hostname for d in self.cdn_domains)

    def validate_target(self, url: str) -> Optional[str]:
        if not url.startswith(("http://", "https://")):
            return "URL must start with http:// or https://"
        if not self.is_in_scope(url):
            return "Target is out of scope"
        if self.is_cdn(url):
            return "Target appears to be a CDN edge — consider scanning the origin IP directly"
        return None


def load_scope_from_dict(data: dict) -> ScopeConfig:
    cfg = ScopeConfig()
    for entry in data.get("in_scope", []):
        if isinstance(entry, str):
            cfg.in_scope.append(ScopeRule(pattern=entry))
        elif isinstance(entry, dict):
            cfg.in_scope.append(ScopeRule(**entry))
    for entry in data.get("out_of_scope", []):
        if isinstance(entry, str):
            cfg.out_of_scope.append(ScopeRule(pattern=entry, is_included=False))
        elif isinstance(entry, dict):
            cfg.out_of_scope.append(ScopeRule(is_included=False, **entry))
    return cfg
