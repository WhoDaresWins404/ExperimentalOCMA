from typing import Optional
from pathlib import Path

import yaml


class FrameworkChecker:
    """Runs framework-specific CVE probes based on detected technology stack."""

    def __init__(self, data_dir: str = ""):
        self._checks = self._load_checks(data_dir)

    def _load_checks(self, data_dir: str) -> dict:
        checks_dir = Path(data_dir) / "framework_checks"
        checks = {}
        if checks_dir.exists():
            for fpath in checks_dir.glob("*.yaml"):
                try:
                    data = yaml.safe_load(fpath.read_text())
                    if data:
                        checks.update(data)
                except Exception:
                    pass
        return checks or self._builtin_checks()

    @staticmethod
    def _builtin_checks() -> dict:
        return {
            "wordpress": {
                "paths": [
                    {"url": "/wp-content/plugins/akismet/readme.txt", "type": "plugin-version"},
                    {"url": "/wp-json/wp/v2/users", "type": "user-enum"},
                    {"url": "/?author=1", "type": "user-enum"},
                    {"url": "/xmlrpc.php", "type": "xmlrpc", "detect": "XML-RPC"},
                    {"url": "/wp-config.php.bak", "type": "config-leak"},
                    {"url": "/wp-content/debug.log", "type": "debug-log"},
                ],
                "cves": [
                    {"cve": "CVE-2021-29447", "description": "XXE in WordPress media upload", "detect": ""},
                ],
            },
            "laravel": {
                "paths": [
                    {"url": "/artisan", "type": "framework-exposed"},
                    {"url": "/storage/logs/laravel.log", "type": "log-leak"},
                    {"url": "/.env", "type": "env-leak", "detect": "APP_KEY"},
                    {"url": "/config/cache.php", "type": "config-leak"},
                    {"url": "/debugbar/open", "type": "debug-mode"},
                ],
            },
            "django": {
                "paths": [
                    {"url": "/admin/", "type": "admin-panel"},
                    {"url": "/api/", "type": "api-root"},
                    {"url": "/graphql", "type": "graphql"},
                    {"url": "/static/", "type": "static-files"},
                ],
            },
            "spring": {
                "paths": [
                    {"url": "/actuator", "type": "actuator", "detect": "actuator"},
                    {"url": "/actuator/health", "type": "actuator-health", "detect": "status"},
                    {"url": "/actuator/env", "type": "actuator-env", "detect": "java"},
                    {"url": "/actuator/heapdump", "type": "heapdump"},
                    {"url": "/actuator/threaddump", "type": "threaddump"},
                    {"url": "/swagger-ui.html", "type": "swagger"},
                    {"url": "/v2/api-docs", "type": "swagger-json"},
                ],
                "cves": [
                    {"cve": "CVE-2022-22965", "description": "Spring4Shell RCE", "detect": ""},
                    {"cve": "CVE-2021-44228", "description": "Log4Shell JNDI injection", "detect": ""},
                ],
            },
            "express": {
                "paths": [
                    {"url": "/.env", "type": "env-leak"},
                    {"url": "/debug/", "type": "debug-mode"},
                ],
            },
            "aws": {
                "checks": [
                    {"type": "s3-bucket", "description": "Check for open S3 buckets from domain name"},
                    {"type": "metadata-service", "description": "Check for 169.254.169.254 access (via SSRF)"},
                ],
            },
            "graphql": {
                "paths": [
                    {"url": "/graphql?query={__schema{types{name}}}", "type": "introspection"},
                    {"url": "/graphql?query={__typename}", "type": "introspection"},
                ],
            },
        }

    def get_checks_for(self, framework: str) -> dict:
        return self._checks.get(framework, {})

    def get_paths(self, framework: str) -> list[dict]:
        return self._checks.get(framework, {}).get("paths", [])

    def get_cves(self, framework: str) -> list[dict]:
        return self._checks.get(framework, {}).get("cves", [])

    def all_paths(self, frameworks: list[str]) -> list[dict]:
        paths = []
        for fw in frameworks:
            paths.extend(self.get_paths(fw))
        return paths
