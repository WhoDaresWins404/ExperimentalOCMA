from pathlib import Path

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType


DIR_WORDLIST_PATH = Path(__file__).parent.parent / "data" / "wordlists" / "directory_paths.txt"

SENSITIVE_FILES = [
    ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
    "wp-config.php", "config.php", "config.inc.php", "config.json",
    "database.yml", "credentials.yml", "secrets.yml",
    ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    "composer.json", "package.json", "yarn.lock", "Gemfile",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "Makefile", "Procfile", ".gitignore",
    "index.php.bak", "index.php~", "index.php.old",
    "admin.php", "login.php", "setup.php", "install.php",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "README.md", "CHANGELOG.md", "LICENSE",
]

ADMIN_PATHS = [
    "admin", "administrator", "adminpanel", "cpanel", "dashboard",
    "manager", "management", "panel", "controlpanel",
    "wp-admin", "administrator", "backend", "cms", "console",
    "login", "signin", "auth", "secure",
    "phpmyadmin", "phpPgAdmin", "adminer", "mysqladmin",
    "logs", "log", "error_log", "debug",
    "uploads", "upload", "files", "download", "downloads",
    "backup", "backups", "old", "dev", "test", "temp", "tmp",
]


@register_scanner
class DirectoryScanner(BaseScanner):
    name = "directory_scanner"

    def __init__(self, config, session_id, waf_state=None):
        super().__init__(config, session_id, waf_state)
        self.wordlist = self._load_wordlist()

    def _load_wordlist(self) -> list[str]:
        path = DIR_WORDLIST_PATH
        paths = set()
        if path.exists():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        paths.add(line)
        paths.update(SENSITIVE_FILES)
        paths.update(ADMIN_PATHS)
        return list(paths)

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        base_url = target.url.rstrip("/")
        seen = set()

        protected_dirs: set[str] = set()
        git_403: set[str] = set()
        backup_403: set[str] = set()

        for path in self.effective_wordlist:
            url = f"{base_url}/{path.lstrip('/')}"
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = await self.request("GET", url)
            except Exception:
                continue

            if resp.status_code in (200, 204, 301, 302, 403, 401):
                ep_type = self._classify_path(path, resp)
                ep = self.make_endpoint(
                    url=url, method="GET", type_hint=ep_type,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    response_body=resp.text,
                    metadata={"path": path, "content_length": len(resp.text)},
                )
                endpoints.append(ep)

                lower = path.lower()

                if ".git" in lower and resp.status_code != 200:
                    git_403.add(path)
                    continue

                if lower.endswith((".bak", ".old", "~", ".swp", ".save")) and resp.status_code != 200:
                    backup_403.add(path)
                    continue

                if resp.status_code == 403:
                    protected_dirs.add(path)
                    continue

                finding = self._analyze_finding(ep, path, resp)
                if finding:
                    findings.append(finding)

        if git_403:
            sorted_paths = sorted(git_403)
            findings.append(self.make_finding(
                title=f"Git Resources Detected (Blocked): {len(git_403)} paths",
                description=f"Server returned 403 for {len(git_403)} Git metadata paths: {', '.join(sorted_paths)}. "
                            "Server is blocking access but paths are confirmed to exist.",
                severity="medium",
                endpoint=endpoints[0] if endpoints else None,
                evidence={"paths": sorted_paths, "count": len(git_403)},
                tags=["git", "enumeration", "restricted"],
            ))

        if backup_403:
            sorted_paths = sorted(backup_403)
            findings.append(self.make_finding(
                title=f"Backup Files Detected (Blocked): {len(backup_403)} files",
                description=f"Server returned 403 for {len(backup_403)} backup/old file paths: {', '.join(sorted_paths)}. "
                            "Files exist but access is denied — may contain sensitive data if access controls fail.",
                severity="medium",
                endpoint=endpoints[0] if endpoints else None,
                evidence={"paths": sorted_paths, "count": len(backup_403)},
                tags=["backup", "enumeration", "restricted"],
            ))

        if protected_dirs:
            sorted_paths = sorted(protected_dirs)
            findings.append(self.make_finding(
                title=f"Protected Resources Found: {len(protected_dirs)} paths",
                description=f"{len(protected_dirs)} paths returned HTTP 403. These may contain sensitive resources: "
                            f"{', '.join(sorted_paths)}.",
                severity="medium",
                endpoint=endpoints[0] if endpoints else None,
                evidence={"paths": sorted_paths, "count": len(protected_dirs)},
                tags=["restricted", "enumeration"],
            ))

        return findings, endpoints

    def _classify_path(self, path: str, resp) -> EndpointType:
        lower = path.lower()
        if any(ext in lower for ext in [".git", ".env", ".htaccess", ".htpasswd", "credentials", "secret"]):
            return EndpointType.BACKUP_FILE
        if any(a in lower for a in ["admin", "panel", "login", "dashboard", "cms"]):
            return EndpointType.ADMIN_PANEL
        if any(b in lower for b in [".bak", ".old", "backup", "dump", ".sql", ".zip", ".tar"]):
            return EndpointType.BACKUP_FILE
        if resp.status_code == 403:
            return EndpointType.HIDDEN_PATH
        return EndpointType.HIDDEN_PATH

    def _analyze_finding(self, ep: Endpoint, path: str, resp) -> dict | None:
        lower = path.lower()

        if ".git" in lower:
            if resp.status_code == 200 and "config" in path and ("repositoryformatversion" in (resp.text or "")):
                return self.make_finding(
                    title="Exposed .git Repository",
                    description=f".git directory exposed at {ep.url}. Full repository may be downloadable.",
                    severity="critical", endpoint=ep,
                    evidence={"url": ep.url, "status": resp.status_code, "size": len(resp.text or "")},
                    tags=["git", "exposure", "scm"],
                )
            if resp.status_code == 200:
                return self.make_finding(
                    title=f".git Resource Accessible: {path}",
                    description=f"Git resource accessible at {ep.url} (HTTP {resp.status_code})",
                    severity="high", endpoint=ep,
                    evidence={"path": path, "status": resp.status_code},
                    tags=["git", "exposure"],
                )

        if ".env" in lower and resp.status_code == 200:
            return self.make_finding(
                title="Exposed .env File",
                description=f"Environment file exposed at {ep.url}. May contain secrets, API keys, credentials.",
                severity="critical", endpoint=ep,
                evidence={"url": ep.url, "content_preview": (resp.text or "")[:500]},
                tags=["env", "exposure", "secrets"],
            )

        if lower.endswith((".bak", ".old", "~", ".swp", ".save")) and resp.status_code == 200:
            return self.make_finding(
                title=f"Backup File Exposed: {path}",
                description=f"Backup/old version of file accessible at {ep.url} (HTTP {resp.status_code})",
                severity="high", endpoint=ep,
                evidence={"path": path, "status": resp.status_code},
                tags=["backup", "exposure"],
            )

        if any(a in lower for a in ["admin", "panel", "dashboard", "login"]) and resp.status_code == 200:
            return self.make_finding(
                title=f"Admin Panel Found: {path}",
                description=f"Administrative interface accessible at {ep.url}",
                severity="high", endpoint=ep,
                evidence={"url": ep.url, "status": resp.status_code, "size": len(resp.text or "")},
                tags=["admin", "exposure"],
            )

        if "robots.txt" in lower and resp.status_code == 200:
            return self.make_finding(
                title="Robots.txt Found",
                description=f"Robots.txt accessible at {ep.url}. May reveal hidden/disallowed paths.",
                severity="low", endpoint=ep,
                evidence={"content": (resp.text or "")[:2000]},
                tags=["robots", "discovery"],
            )

        if "phpinfo" in lower and resp.status_code == 200:
            return self.make_finding(
                title="PHPInfo Exposed",
                description=f"PHP configuration page exposed at {ep.url}. Reveals system information.",
                severity="critical", endpoint=ep,
                evidence={"url": ep.url},
                tags=["phpinfo", "exposure", "information_disclosure"],
            )

        if resp.status_code in (301, 302) and path != "":
            location = resp.headers.get("location", "")
            return self.make_finding(
                title=f"Redirect Discovery: {path}",
                description=f"Path redirects to {location}",
                severity="low", endpoint=ep,
                evidence={"from": ep.url, "to": location},
                tags=["redirect", "discovery"],
            )

        return None
