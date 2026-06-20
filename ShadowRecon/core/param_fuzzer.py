import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Optional


PARAM_CLASSIFIERS = [
    ("numeric", re.compile(r"^\d+$")),
    ("url", re.compile(r"^https?://")),
    ("file", re.compile(r"^[./\\]")),
    ("slug", re.compile(r"^[a-z0-9-]+$", re.I)),
    ("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("email", re.compile(r"^[^@]+@[^@]+\.[^@]+$")),
]

PARAM_TYPE_MAP = {
    "numeric": {"idor", "mass-assignment"},
    "url": {"ssrf", "open-redirect", "redirect"},
    "file": {"lfi", "path-traversal", "rfi"},
    "slug": {"idor"},
    "uuid": {"idor"},
}

PARAM_NAME_HINTS: dict[str, set[str]] = {
    "id": {"idor"}, "user_id": {"idor"}, "uid": {"idor"}, "account": {"idor"},
    "file": {"lfi"}, "page": {"lfi"}, "path": {"lfi"}, "document": {"lfi"},
    "url": {"ssrf", "redirect"}, "redirect": {"redirect"}, "next": {"redirect"},
    "return": {"redirect"}, "callback": {"ssrf"}, "webhook": {"ssrf"},
    "email": {"ssti:email"}, "name": {"ssti:name"}, "message": {"ssti"},
}


class ParamFuzzer:
    def __init__(self):
        self._registry: dict[str, list[dict]] = {}

    def extract_params(self, urls: list[str]) -> list[dict]:
        params = []
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for name, values in query_params.items():
                param = {"name": name, "value": values[0] if values else "", "source_url": url, "classifications": set()}
                matched_class = self._classify(values[0] if values else "", name)
                param["classifications"] = matched_class
                params.append(param)
        return params

    def _classify(self, value: str, name: str) -> set[str]:
        classifications = set()
        hint = PARAM_NAME_HINTS.get(name.lower())
        if hint:
            classifications.update(hint)
        for cls_name, pattern in PARAM_CLASSIFIERS:
            if pattern.match(value):
                classifications.add(cls_name)
                attack_types = PARAM_TYPE_MAP.get(cls_name, set())
                classifications.update(attack_types)
        return classifications

    def suggest_scanners(self, params: list[dict]) -> dict[str, list[str]]:
        suggestions: dict[str, list[str]] = {}
        scanner_map = {
            "idor": "idor_scanner",
            "ssrf": "ssrf_scanner",
            "lfi": "lfi_scanner",
            "open-redirect": "redirect_scanner",
            "ssti": "ssti_scanner",
        }
        for p in params:
            for vuln_type in p["classifications"]:
                scanner = scanner_map.get(vuln_type)
                if scanner:
                    suggestions.setdefault(scanner, []).append(p["name"])
        return suggestions
