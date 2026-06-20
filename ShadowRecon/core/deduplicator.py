import hashlib
import re
import json
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from typing import Iterable, Optional
from Levenshtein import ratio as levenshtein_ratio

from .models import Finding, Endpoint


class Deduplicator:
    def __init__(self, exact_threshold: float = 1.0, structural_threshold: float = 0.95, fuzzy_threshold: float = 0.85):
        self.exact_threshold = exact_threshold
        self.structural_threshold = structural_threshold
        self.fuzzy_threshold = fuzzy_threshold
        self._fingerprints: dict[str, str] = {}
        self._existing_findings: dict[str, Finding] = {}

    @staticmethod
    def canonicalize_url(url: str) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") or "/"
        params = sorted(parse_qs(parsed.query, keep_blank_values=True).items())
        query = urlencode([(k, v[0]) for k, v in params]) if params else ""
        fragment = ""
        return urlunparse((scheme, netloc, path, parsed.params, query, fragment))

    @staticmethod
    def fingerprint_url(url: str, method: str) -> str:
        canonical = Deduplicator.canonicalize_url(url)
        raw = f"{method.upper()}:{canonical}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def fingerprint_response(status_code: int, content_type: str = "", content_length: int = 0) -> str:
        length_bucket = content_length // 100 * 100
        raw = f"{status_code}:{content_type}:{length_bucket}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def fingerprint_finding(finding: Finding) -> str:
        title = re.sub(r"\s+", " ", finding.title.strip().lower())
        desc = re.sub(r"\s+", " ", finding.description.strip().lower())[:200]
        raw = f"{finding.scanner_name}:{title}:{desc}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_duplicate_endpoint(self, endpoint: Endpoint) -> Optional[str]:
        fp = self.fingerprint_url(endpoint.url, endpoint.method)
        if fp in self._fingerprints:
            return self._fingerprints[fp]
        self._fingerprints[fp] = endpoint.id
        return None

    async def dedup_endpoints(self, endpoints: list[Endpoint], existing: list[Endpoint] = None) -> list[Endpoint]:
        seen: dict[str, Endpoint] = {}
        deduped: list[Endpoint] = []
        for ep in endpoints:
            fp = self.fingerprint_url(ep.url, ep.method)
            if fp not in seen:
                seen[fp] = ep
                deduped.append(ep)
        return deduped

    async def dedup_findings(self, findings: list[Finding]) -> list[Finding]:
        exact_seen: dict[str, Finding] = {}
        structural_groups: dict[str, list[Finding]] = {}
        deduped: list[Finding] = []

        for f in findings:
            fp = self.fingerprint_finding(f)
            if fp in exact_seen:
                survivor = exact_seen[fp]
                survivor.duplicates.append(f.id)
                f.duplicate_of = survivor.id
                if isinstance(f.evidence, dict):
                    survivor.evidence.update(f.evidence)
                continue

            struct_key = f"{f.scanner_name}:{f.severity.value}:{f.endpoint_id or ''}"
            if struct_key not in structural_groups:
                structural_groups[struct_key] = []
            structural_groups[struct_key].append(f)

        for group in structural_groups.values():
            if len(group) == 1:
                deduped.append(group[0])
                exact_seen[self.fingerprint_finding(group[0])] = group[0]
                continue

            merged = group[0]
            for other in group[1:]:
                similarity = levenshtein_ratio(
                    re.sub(r"\s+", " ", merged.title.strip().lower()),
                    re.sub(r"\s+", " ", other.title.strip().lower()),
                )
                if similarity >= self.fuzzy_threshold:
                    merged.duplicates.append(other.id)
                    other.duplicate_of = merged.id
                    if isinstance(other.evidence, dict):
                        merged.evidence.update(other.evidence)
                    if other.cvss_score and (merged.cvss_score is None or other.cvss_score > merged.cvss_score):
                        merged.cvss_score = other.cvss_score
                        merged.cvss_vector = other.cvss_vector
                else:
                    deduped.append(other)
                    exact_seen[self.fingerprint_finding(other)] = other

            deduped.append(merged)
            exact_seen[self.fingerprint_finding(merged)] = merged

        return deduped

    async def dedup_endpoints_stream(self, endpoints: Iterable[Endpoint]) -> list[Endpoint]:
        seen: dict[str, Endpoint] = {}
        deduped: list[Endpoint] = []
        for ep in endpoints:
            fp = self.fingerprint_url(ep.url, ep.method)
            if fp not in seen:
                seen[fp] = ep
                deduped.append(ep)
        return deduped

    async def dedup_findings_stream(self, findings: Iterable[Finding]) -> list[Finding]:
        exact_seen: dict[str, Finding] = {}
        structural_groups: dict[str, list[Finding]] = {}
        deduped: list[Finding] = []

        for f in findings:
            fp = self.fingerprint_finding(f)
            if fp in exact_seen:
                survivor = exact_seen[fp]
                survivor.duplicates.append(f.id)
                f.duplicate_of = survivor.id
                if isinstance(f.evidence, dict):
                    survivor.evidence.update(f.evidence)
                continue

            struct_key = f"{f.scanner_name}:{f.severity.value}:{f.endpoint_id or ''}"
            if struct_key not in structural_groups:
                structural_groups[struct_key] = []
            structural_groups[struct_key].append(f)

        for group in structural_groups.values():
            if len(group) == 1:
                deduped.append(group[0])
                exact_seen[self.fingerprint_finding(group[0])] = group[0]
                continue

            merged = group[0]
            for other in group[1:]:
                similarity = levenshtein_ratio(
                    re.sub(r"\s+", " ", merged.title.strip().lower()),
                    re.sub(r"\s+", " ", other.title.strip().lower()),
                )
                if similarity >= self.fuzzy_threshold:
                    merged.duplicates.append(other.id)
                    other.duplicate_of = merged.id
                    if isinstance(other.evidence, dict):
                        merged.evidence.update(other.evidence)
                    if other.cvss_score and (merged.cvss_score is None or other.cvss_score > merged.cvss_score):
                        merged.cvss_score = other.cvss_score
                        merged.cvss_vector = other.cvss_vector
                else:
                    deduped.append(other)
                    exact_seen[self.fingerprint_finding(other)] = other

            deduped.append(merged)
            exact_seen[self.fingerprint_finding(merged)] = merged

        return deduped

    async def reset(self):
        self._fingerprints.clear()
        self._existing_findings.clear()
