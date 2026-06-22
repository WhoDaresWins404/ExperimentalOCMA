import json
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

WEB3_PATHS = [
    "/v1", "/v2", "/rpc", "/api/rpc",
    "/infura", "/alchemy", "/moralis",
    "/.well-known/ethereum",
    "/contract", "/api/contract",
    "/wallet", "/api/wallet",
    "/token", "/api/token",
    "/nft", "/api/nft",
    "/dapp", "/api/dapp",
    "/swap", "/bridge",
    "/blockchain", "/api/blockchain",
]

RPC_PROBE = {
    "jsonrpc": "2.0",
    "method": "eth_chainId",
    "params": [],
    "id": 1,
}

CHAIN_ID_METHODS = [
    "eth_chainId", "net_version", "eth_blockNumber",
    "web3_clientVersion", "eth_getBalance",
]

PRIVATE_KEY_PATTERNS = [
    r'0x[0-9a-fA-F]{64}',
    r'[0-9a-fA-F]{64}',
]

SEED_PHRASE_PATTERNS = [
    r'\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|agree|ahead|aid)\b',
]

RPC_ENDPOINTS = [
    "https://eth-mainnet.g.alchemy.com/v2/",
    "https://mainnet.infura.io/v3/",
    "https://eth-mainnet.public.blastapi.io",
]


@register_scanner(manifest=ScannerManifest(
    name="web3_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=50,
    produces_tag_patterns=["web3", "blockchain", "ethereum", "rpc", "smart-contract"],
    produces_endpoint_types=[],
))
class Web3Scanner(BaseScanner):
    name = "web3_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        for path in WEB3_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url, follow_redirects=True)
                self._stats["requests"] += 1
                body = (resp.text or "").lower()
                if any(kw in body for kw in ["ethereum", "eth_", "web3", "solidity",
                                               "metamask", "walletconnect", "0x"]):
                    ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                    endpoints.append(ep)
                    findings.append(self.make_finding(
                        title="Web3 / Blockchain Surface Detected",
                        description=f"Web3-related content found at {url}. Blockchain endpoint may be exposed.",
                        severity=FindingSeverity.MEDIUM.value,
                        endpoint=ep,
                        evidence={"url": url, "body_preview": body[:200]},
                        confidence=0.75,
                        tags=["web3", "blockchain", "exposure"],
                    ))
            except Exception:
                self._stats["errors"] += 1

            try:
                rpc_resp = await client.post(url, json=RPC_PROBE,
                                              headers={"Content-Type": "application/json"})
                self._stats["requests"] += 1
                if rpc_resp.status_code == 200:
                    rpc_data = rpc_resp.json()
                    if isinstance(rpc_data, dict) and "result" in rpc_data:
                        chain_id = rpc_data.get("result")
                        ep = self.make_endpoint(url=url, status_code=200, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="Web3 — JSON-RPC Endpoint Exposed",
                            description=f"Public JSON-RPC endpoint at {url}. Chain ID: {chain_id}. "
                                        f"This endpoint may allow direct blockchain queries.",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={
                                "url": url,
                                "chain_id": chain_id,
                                "rpc_response": rpc_data,
                            },
                            confidence=0.95,
                            tags=["web3", "json-rpc", "blockchain", "rpc-exposure"],
                        ))
            except Exception:
                self._stats["errors"] += 1

        try:
            html_resp = await client.get(target.url)
            self._stats["requests"] += 1
            html = html_resp.text or ""
            import re
            private_keys = set(re.findall(r'0x[0-9a-fA-F]{64}', html))
            if private_keys:
                ep = self.make_endpoint(url=target.url, status_code=html_resp.status_code, discovered_by=self.name)
                endpoints.append(ep)
                findings.append(self.make_finding(
                    title="Web3 — Hardcoded Private Keys in Frontend",
                    description=f"Found {len(private_keys)} potential Ethereum private keys in page source at {target.url}.",
                    severity=FindingSeverity.CRITICAL.value,
                    endpoint=ep,
                    evidence={"url": target.url, "keys_found": list(private_keys)[:5]},
                    confidence=0.6,
                    tags=["web3", "private-key", "credential-exposure", "crypto"],
                ))
            seed_words = re.findall(r'\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|agree|ahead|aid)\b', html)
            if len(seed_words) >= 12:
                ep2 = self.make_endpoint(url=target.url, status_code=html_resp.status_code, discovered_by=self.name)
                endpoints.append(ep2)
                findings.append(self.make_finding(
                    title="Web3 — Seed Phrase / Mnemonic Detected",
                    description=f"Found {len(seed_words)} BIP-39 seed words in page source. Possible wallet mnemonic exposure.",
                    severity=FindingSeverity.CRITICAL.value,
                    endpoint=ep2,
                    evidence={"url": target.url, "seed_words_sample": seed_words[:12]},
                    confidence=0.5,
                    tags=["web3", "seed-phrase", "credential-exposure", "crypto"],
                ))
        except Exception:
            pass

        return findings, endpoints
