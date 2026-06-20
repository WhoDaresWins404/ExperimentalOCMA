import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader


class PoCGenerator:
    def __init__(self):
        self._env = Environment(loader=FileSystemLoader(
            str(Path(__file__).parent / "templates")
        ))

    def curl_command(self, finding: dict) -> str:
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        evidence = {}
        if isinstance(finding.get("evidence"), dict):
            evidence = finding["evidence"]
        headers = evidence.get("request_headers", {})
        body = evidence.get("request_body", "")
        parts = ["curl"]
        if method != "GET":
            parts.append(f"-X {method}")
        for k, v in headers.items():
            if k.lower() not in ("content-length",):
                parts.append(f"-H '{k}: {v}'")
        if body:
            escaped = body.replace("'", "'\\''")
            parts.append(f"-d '{escaped}'")
        parts.append(f"'{url}'")
        return " \\\n  ".join(parts)

    def python_poc(self, finding: dict) -> str:
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        evidence = {}
        if isinstance(finding.get("evidence"), dict):
            evidence = finding["evidence"]
        headers = evidence.get("request_headers", {})
        body = evidence.get("request_body", "")
        lines = [
            "import requests",
            "",
            f"url = {repr(url)}",
            f"headers = {json.dumps(headers, indent=2)}",
        ]
        if body:
            lines.append(f"data = {repr(body)}")
            lines.append(f"r = requests.{method.lower()}(url, headers=headers, data=data)")
        else:
            lines.append(f"r = requests.{method.lower()}(url, headers=headers)")
        lines.extend([
            "",
            "print(f'Status: {r.status_code}')",
            "print(f'Headers: {dict(r.headers)}')",
            "print(f'Body: {r.text[:2000]}')",
        ])
        return "\n".join(lines)

    def html_poc(self, finding: dict) -> str:
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        evidence = {}
        if isinstance(finding.get("evidence"), dict):
            evidence = finding["evidence"]
        body = evidence.get("request_body", "")
        params = evidence.get("params", {})
        hidden_fields = "\n".join(
            f'    <input type="hidden" name="{k}" value="{v}">'
            for k, v in (params or {}).items()
        )
        tpl = self._env.get_template("poc.html.j2")
        return tpl.render(
            url=url,
            method=method,
            body=body,
            hidden_fields=hidden_fields,
            title=finding.get("title", "PoC"),
        )

    def hackerone_report(self, finding: dict) -> str:
        tpl = self._env.get_template("hackerone.md.j2")
        return tpl.render(
            title=finding.get("title", ""),
            severity=finding.get("severity", "medium"),
            description=finding.get("description", ""),
            url=finding.get("url", ""),
            remediation=finding.get("remediation", ""),
            curl=self.curl_command(finding),
            timestamp=datetime.utcnow().isoformat(),
        )

    def bugcrowd_report(self, finding: dict) -> str:
        tpl = self._env.get_template("bugcrowd.md.j2")
        return tpl.render(
            title=finding.get("title", ""),
            severity=finding.get("severity", "medium"),
            description=finding.get("description", ""),
            url=finding.get("url", ""),
            steps_to_reproduce=finding.get("evidence", {}).get("steps", ""),
            impact=finding.get("evidence", {}).get("impact", ""),
            remediation=finding.get("remediation", ""),
            curl=self.curl_command(finding),
            timestamp=datetime.utcnow().isoformat(),
        )
