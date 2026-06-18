from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4


class ScanStatus(str, Enum):
    PENDING = "pending"
    WAF_CHECK = "waf_check"
    RECONNAISSANCE = "reconnaissance"
    STRATEGIZE = "strategize"
    SCANNING = "scanning"
    ADAPTIVE_SCAN = "adaptive_scan"
    DEDUP = "dedup"
    LLM_ENRICH = "llm_enrich"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class FindingSeverity(str, Enum):
    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EndpointType(str, Enum):
    API_REST = "api_rest"
    API_GRAPHQL = "api_graphql"
    API_SOAP = "api_soap"
    WEB_PAGE = "web_page"
    STATIC_ASSET = "static_asset"
    ADMIN_PANEL = "admin_panel"
    BACKUP_FILE = "backup_file"
    HIDDEN_PATH = "hidden_path"
    AUTH_PROVIDER = "auth_provider"
    DATABASE = "database"
    UNKNOWN = "unknown"


class NodeType(str, Enum):
    HOST = "host"
    ENDPOINT = "endpoint"
    API = "api"
    PARAMETER = "parameter"
    AUTH_PROVIDER = "auth_provider"
    DATABASE = "database"
    STATIC_ASSET = "static_asset"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class EdgeType(str, Enum):
    HTTP_LINKS_TO = "http_links_to"
    API_CALLS = "api_calls"
    AUTHENTICATES_VIA = "authenticates_via"
    EMBEDS_RESOURCE = "embeds_resource"
    REDIRECTS_TO = "redirects_to"
    SHARES_COOKIE_DOMAIN = "shares_cookie_domain"
    DEPENDS_ON = "depends_on"
    PARSES_AS_PARAM = "parses_as_param"
    PROBES_TO = "probes_to"


class Campaign(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    name: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanSession(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    campaign_id: str
    target: str
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    error_log: list[str] = Field(default_factory=list)


class ScanTarget(BaseModel):
    url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class Endpoint(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    session_id: str
    url: str
    method: str = "GET"
    type: EndpointType = EndpointType.UNKNOWN
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    response_hash: Optional[str] = None
    response_size: Optional[int] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_by: str = ""
    source: str = ""
    found_at: datetime = Field(default_factory=datetime.utcnow)


class CVSSVector(BaseModel):
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"

    def compute_score(self) -> float:
        impact = 6.42
        exploitability = 8.22
        if self.confidentiality != "N" or self.integrity != "N" or self.availability != "N":
            impact = 10.41
        if self.scope == "C":
            impact = 7.52 if impact == 6.42 else 9.41
        base = round(min(impact + exploitability, 10), 1)
        return base

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    session_id: str
    endpoint_id: Optional[str] = None
    scanner_name: str
    title: str
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    cvss_vector: Optional[CVSSVector] = None
    cvss_score: Optional[float] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    raw_response_ids: list[str] = Field(default_factory=list)
    duplicate_of: Optional[str] = None
    duplicates: list[str] = Field(default_factory=list)
    is_llm_enhanced: bool = False
    llm_analysis: Optional["LLMAnalysis"] = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    found_at: datetime = Field(default_factory=datetime.utcnow)


class LLMAnalysis(BaseModel):
    natural_description: str = ""
    impact_analysis: str = ""
    suggested_cvss_vector: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    raw_response: str = ""
    model_used: str = ""
    processing_time_ms: int = 0


class ScanResult(BaseModel):
    session_id: str
    target: str
    status: ScanStatus
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    raw_responses: list[dict] = Field(default_factory=list)
    graph_nodes: list["GraphNode"] = Field(default_factory=list)
    graph_edges: list["GraphEdge"] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
    session_id: str
    total_endpoints: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_duration_seconds: float = 0.0
    endpoints_by_type: dict[str, int] = Field(default_factory=dict)
    findings_by_scanner: dict[str, int] = Field(default_factory=dict)
    top_risks: list[str] = Field(default_factory=list)
    llm_summary: str = ""


class GraphNode(BaseModel):
    id: str
    session_id: str
    node_type: NodeType
    label: str
    url: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    session_id: str
    source_node: str
    target_node: str
    edge_type: EdgeType
    label: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Adaptive scan intelligence models ─────────────────────────────

@dataclass
class TechFingerprint:
    """Result of Phase 0 reconnaissance — what tech does the target run?"""
    server: Optional[str] = None
    framework: Optional[str] = None
    framework_confidence: float = 0.0
    cms: Optional[str] = None
    scripting: Optional[str] = None
    waf: Optional[str] = None
    cookies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    exposed_paths: list[str] = field(default_factory=list)


@dataclass
class Directive:
    """An instruction from IntelligenceCore to a scanner or group of scanners."""
    target: str                         # scanner name or "all"
    action: str                         # "augment_wordlist", "skip", "adjust_param", "enable_check"
    payload: Any = None
    reason: str = ""
    priority: int = 1                   # 0=info, 1=suggest, 2=enforce
    expires_after: Optional[int] = None # scanner runs before auto-expire


@dataclass
class ScannerManifest:
    """Metadata about a registered scanner for the scheduler."""
    name: str
    category: str = "discovery"         # "recon", "discovery", "exploit", "analysis"
    risk_level: str = "safe"            # "safe", "moderate", "aggressive"
    prerequisites: list[str] = field(default_factory=list)
    estimated_cost: int = 50            # 1–100 relative time cost
    produces_endpoint_types: list[str] = field(default_factory=list)
    produces_tag_patterns: list[str] = field(default_factory=list)


@dataclass
class ScanStrategy:
    """Optional LLM-generated scan strategy for Phase 1."""
    priority_scanners: list[str] = field(default_factory=list)
    skip_scanners: list[str] = field(default_factory=list)
    augmented_wordlists: dict[str, list[str]] = field(default_factory=dict)
    parameter_focus: list[str] = field(default_factory=list)
    optimal_crawl_depth: int = 1
    enable_exploit_mode: bool = False
    rationale: str = ""


@dataclass
class ScanProfile:
    """Compiled scan profile from intelligence fingerprinting + optional LLM strategy."""
    scanner_priorities: dict[str, int] = field(default_factory=dict)
    skipped_scanners: list[str] = field(default_factory=list)
    augmented_wordlists: dict[str, list[str]] = field(default_factory=dict)
    parameter_focus: list[str] = field(default_factory=list)
    crawl_depth: int = 1
    exploit_mode: bool = False
    evasion_mode: bool = False

    @classmethod
    def from_fingerprint(cls, fp: TechFingerprint, llm_strategy: Optional[ScanStrategy] = None):
        profile = cls()

        # Framework-based wordlist augmentation
        framework_dirs = {
            "wordpress": ["/wp-admin", "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-content/uploads/"],
            "laravel": ["/storage", "/_ignition", "/config", "/storage/logs/laravel.log"],
            "express": ["/.env", "/package.json", "/debug/", "/app.js"],
            "django": ["/admin/", "/api/", "/graphql"],
            "rails": ["/rails/info", "/assets/", "/sidekiq"],
        }

        if fp.framework and fp.framework_confidence >= 0.6:
            dirs = framework_dirs.get(fp.framework, [])
            if dirs:
                profile.augmented_wordlists["directory_scanner"] = dirs
                profile.scanner_priorities["directory_scanner"] = 30

        if fp.waf:
            profile.evasion_mode = True

        if llm_strategy:
            for sn in llm_strategy.skip_scanners:
                profile.skipped_scanners.append(sn)
            for sn, pri in [(s, 20) for s in llm_strategy.priority_scanners]:
                profile.scanner_priorities[sn] = pri
            for sn, paths in llm_strategy.augmented_wordlists.items():
                existing = profile.augmented_wordlists.get(sn, [])
                profile.augmented_wordlists[sn] = existing + paths
            profile.crawl_depth = llm_strategy.optimal_crawl_depth
            profile.exploit_mode = llm_strategy.enable_exploit_mode

        return profile

    def to_directives(self) -> list[Directive]:
        dirs = []
        for scanner_name, paths in self.augmented_wordlists.items():
            dirs.append(Directive(scanner_name, "augment_wordlist", paths,
                                  "tech fingerprint", priority=2))
        for sn in self.skipped_scanners:
            dirs.append(Directive(sn, "skip", None, "profile skip", priority=2))
        if self.exploit_mode:
            dirs.append(Directive("form_scanner", "adjust_param", {"xss_mode": "exploit"},
                                  "profile exploit mode", priority=2))
        if self.evasion_mode:
            dirs.append(Directive("all", "adjust_param", {"evasion_headers": {}},
                                  "WAF evasion", priority=1))
        return dirs
