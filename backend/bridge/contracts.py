"""Bridge contracts — Pydantic models defining API response shapes."""
from typing import Optional
from pydantic import BaseModel


# ── Agent Smith ──
class SmithDetection(BaseModel):
    detected: bool
    rule_matches: list[dict] = []
    alert_matches: list[dict] = []
    match_count: int = 0
    commentary: str = ""

class SmithAttackEvent(BaseModel):
    attack_id: str
    timestamp: str
    category: str
    description: str
    detection: SmithDetection

class SmithStatusResponse(BaseModel):
    state: str
    active: bool
    session_id: Optional[str] = None
    intensity: Optional[int] = None
    categories: list[str] = []
    events_injected: int = 0
    elapsed_seconds: Optional[float] = None
    duration_seconds: int = 0
    attacks_launched: int = 0
    attacks_detected: int = 0
    attacks_missed: int = 0
    attacks_pending: int = 0
    sessions_completed: int = 0
    unique_attacks_generated: int = 0

class SmithSessionResult(BaseModel):
    session_id: str
    timestamp: str
    intensity: int
    duration_seconds: Optional[float] = None
    total_attacks: int
    detected_count: int
    missed_count: int
    detection_rate: float
    verdict: dict
    category_results: dict = {}
    categories_tested: list[str] = []
    weak_categories: list[str] = []
    blind_spots: list[str] = []
    recommendations: list[str] = []


# ── Commander Bond ──
class BondIntelligence(BaseModel):
    generation: int = 0
    source_rankings: list[str] = []
    source_scores: dict = {}
    threat_trend: str = "stable"
    adaptive_interval: int = 21600
    correlations_found: int = 0
    total_threats_analyzed: int = 0

class BondThreat(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    source: str
    bond_assessment: str
    iocs: list[str] = []
    cereberus_prompt: str = ""
    mitre_techniques: list[str] = []

class BondReportResponse(BaseModel):
    id: str
    timestamp: str
    scan_duration_seconds: float
    status: str
    threat_count: int
    threats: list[BondThreat] = []
    summary: str
    all_clear: bool

class BondStatusResponse(BaseModel):
    state: str
    last_scan: Optional[str] = None
    next_scan: Optional[str] = None
    threat_count: int = 0
    scan_interval_seconds: int = 21600
    total_scans: int = 0
    total_threats_found: int = 0
    reports_buffered: int = 0
    neutralized_count: int = 0
    intelligence: Optional[BondIntelligence] = None
    sword: Optional[dict] = None
    overwatch: Optional[dict] = None


# ── Guardian ──
class GuardianStatusResponse(BaseModel):
    containment_level: int = 0
    level_name: str = "GREEN"
    lockdown_active: bool = False
    lockdown_reason: str = ""
    lockdown_at: Optional[str] = None
    stability_score: float = 100.0
    interventions: list[dict] = []
    last_check: Optional[str] = None


# ── Alerts ──
class AlertResponse(BaseModel):
    id: int
    timestamp: str
    severity: str
    module_source: str
    title: str
    description: str
    vpn_status_at_event: Optional[str] = None
    acknowledged: bool = False
    resolved_at: Optional[str] = None
    dismissed: bool = False
    snoozed_until: Optional[str] = None
    escalated_to_incident_id: Optional[int] = None


# ── Network ──
class NetworkConnectionResponse(BaseModel):
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    status: str
    pid: int
    suspicious: bool = False
    dangerous_service: Optional[str] = None


# ── IOC ──
class IOCResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    source: str
    severity: str
    first_seen: str
    last_seen: str
    tags: list[str] = []
    context: dict = {}
    active: bool = True
    feed_id: Optional[int] = None
    confidence: Optional[int] = None
    expires_at: Optional[str] = None
    false_positive: bool = False
    hit_count: int = 0
    last_hit_at: Optional[str] = None


# ── Thresholds ──
class ThresholdResponse(BaseModel):
    key: str
    category: str
    description: str
    current_value: int
    default_value: int
    type: str = "int"


# ── YARA (Phase 15) ──
class YaraRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    enabled: bool = True
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    tags: list[str] = []
    match_count: int = 0
    last_match_at: Optional[str] = None

class YaraScanResultResponse(BaseModel):
    id: int
    scan_type: str
    target: str
    rule_name: str
    rule_namespace: Optional[str] = None
    strings_matched: list[str] = []
    severity: str = "medium"
    scanned_at: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    triggered_by: Optional[str] = None


# ── Memory Scanner (Phase 15) ──
class MemoryScanResultResponse(BaseModel):
    id: int
    pid: int
    process_name: str
    finding_type: str
    severity: str = "medium"
    details: dict = {}
    scanned_at: Optional[str] = None


# ── Sword Protocol (Phase 15) ──
class SwordPolicyResponse(BaseModel):
    id: int
    codename: str
    name: str
    description: Optional[str] = None
    trigger_type: str
    trigger_conditions: dict = {}
    escalation_chain: list[dict] = []
    cooldown_seconds: int = 300
    enabled: bool = True
    requires_confirmation: bool = False
    execution_count: int = 0
    last_triggered: Optional[str] = None

class SwordLogResponse(BaseModel):
    id: int
    policy_id: int
    codename: str
    trigger_event: dict = {}
    actions_taken: list[dict] = []
    result: str
    escalation_level: int = 0
    executed_at: Optional[str] = None
    duration_ms: Optional[int] = None


# ── Overwatch (Phase 15) ──
class OverwatchStatusResponse(BaseModel):
    status: str = "uninitialized"
    files_baselined: int = 0
    tamper_count: int = 0
    last_check: Optional[str] = None
    check_interval_seconds: int = 600
