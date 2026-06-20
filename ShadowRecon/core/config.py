from pydantic import BaseModel, Field
from typing import Optional, Literal
from pathlib import Path


class ProxyConfig(BaseModel):
    enabled: bool = False
    chain: list[str] = Field(default_factory=lambda: [
        "socks5://127.0.0.1:9050",
    ])
    rotation: Literal["round_robin", "random"] = "random"
    per_request: bool = False


class AuthConfig(BaseModel):
    enabled: bool = False
    auth_type: Literal["none", "cookie", "bearer", "header", "basic"] = "none"
    cookie_string: str = ""
    bearer_token: str = ""
    header_key: str = ""
    header_value: str = ""
    basic_username: str = ""
    basic_password: str = ""


class LLMConfig(BaseModel):
    enabled: bool = False
    provider: Literal["ollama", "openai"] = "ollama"
    ollama_host: str = "http://192.168.50.228:11434"
    model_name: str = "RedQueen"
    api_key: str = ""
    api_base: str = ""
    temperature: float = 0.3
    max_tokens: int = 2048
    timeout: int = 60
    enrich_findings: bool = True
    enrich_min_severity: str = "high"
    generate_summary: bool = True
    generate_training_data: bool = True
    payload_gen_enabled: bool = False
    payload_gen_timeout: int = 120
    payload_gen_max_attempts: int = 3
    payload_gen_fallback: bool = True
    strategize: bool = False
    strategize_timeout: int = 120


class EvasionConfig(BaseModel):
    auto_evasion: bool = True
    user_agent_rotation: bool = True
    user_agents: list[str] = Field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
    ])
    request_delay_min: float = 0.1
    request_delay_max: float = 2.0
    jitter: bool = True


class IntelligenceConfig(BaseModel):
    """Controls the adaptive scan intelligence system."""
    enabled: bool = True
    fingerprint: bool = True
    adaptive_wordlists: bool = True
    escalation_rules: bool = True
    context_aware_crawling: bool = True
    time_budgeting: bool = True
    fingerprint_path: str = str(Path(__file__).parent.parent / "data" / "fingerprints")


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./shadowrecon.db"
    echo: bool = False
    pool_size: int = 5


class ScanConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)
    cidr: Optional[str] = None
    port_range: str = "80,443,8080,8443,3000,5000,9090"
    threads: int = 25
    timeout: int = 30
    max_scan_time: int = 3600
    max_response_size: int = 1_048_576
    scan_mode: Literal["full", "light", "waf_only"] = "full"
    detection_mode: Literal["detect", "confirm"] = "detect"
    follow_redirects: bool = True
    max_redirects: int = 5
    depth: int = 2
    max_crawl_pages: int = 50
    max_findings: int = 5000
    max_endpoints: int = 10000
    max_raw_responses: int = 5000
    crawl_mode: bool = True
    xss_mode: str = "probe"
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    enabled_scanners: list[str] = Field(default_factory=list)

    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    evasion: EvasionConfig = Field(default_factory=EvasionConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    intelligence: IntelligenceConfig = Field(default_factory=IntelligenceConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    host_unreachable_timeout: int = 120

    data_dir: str = str(Path(__file__).parent.parent / "data")
    output_dir: str = "./reports"

    class Config:
        use_enum_values = True
