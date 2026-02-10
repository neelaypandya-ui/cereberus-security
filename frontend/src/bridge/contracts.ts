/**
 * Bridge Contracts — TypeScript interfaces mirroring backend Pydantic models.
 * @bridge Auto-generated from backend/bridge/contracts.py
 */


// ── Commander Bond ──

/** @bridge BondIntelligence */
export interface BondIntelligence {
  generation: number;
  source_rankings: string[];
  source_scores: Record<string, { total: number; relevant: number; false_positive: number; severity_sum: number; quality_score: number }>;
  threat_trend: string;
  adaptive_interval: number;
  correlations_found: number;
  total_threats_analyzed: number;
}

/** @bridge BondThreat */
export interface BondThreat {
  id: string;
  name: string;
  category: string;
  severity: string;
  source: string;
  bond_assessment: string;
  iocs: string[];
  cereberus_prompt: string;
  mitre_techniques: string[];
}

/** @bridge BondReportResponse */
export interface BondReportResponse {
  id: string;
  timestamp: string;
  scan_duration_seconds: number;
  status: string;
  threat_count: number;
  threats: BondThreat[];
  summary: string;
  all_clear: boolean;
}

/** @bridge BondStatusResponse */
export interface BondStatusResponse {
  state: string;
  last_scan: string | null;
  next_scan: string | null;
  threat_count: number;
  scan_interval_seconds: number;
  total_scans: number;
  total_threats_found: number;
  reports_buffered: number;
  neutralized_count: number;
  intelligence: BondIntelligence | null;
  sword: SwordStats | null;
  overwatch: OverwatchStatus | null;
}


// ── Guardian ──

/** @bridge GuardianStatusResponse */
export interface GuardianStatusResponse {
  containment_level: number;
  level_name: string;
  lockdown_active: boolean;
  lockdown_reason: string;
  lockdown_at: string | null;
  stability_score: number;
  interventions: Array<{
    timestamp: string;
    level: string;
    reason: string;
    stability_score: number;
    action_taken: string;
  }>;
  last_check: string | null;
}


// ── Alerts ──

/** @bridge AlertResponse */
export interface AlertResponse {
  id: number;
  timestamp: string;
  severity: string;
  module_source: string;
  title: string;
  description: string;
  vpn_status_at_event: string | null;
  acknowledged: boolean;
  resolved_at: string | null;
  dismissed: boolean;
  snoozed_until: string | null;
  escalated_to_incident_id: number | null;
  details_json?: Record<string, unknown>;
  interface_name?: string;
  feedback?: string;
  feedback_at?: string;
  feedback_by?: string;
}


// ── Network ──

/** @bridge NetworkConnectionResponse */
export interface NetworkConnectionResponse {
  local_addr: string;
  local_port: number;
  remote_addr: string | null;
  remote_port: number | null;
  protocol: string;
  status: string;
  pid: number;
  suspicious: boolean;
  dangerous_service: string | null;
}


// ── IOC ──

/** @bridge IOCResponse */
export interface IOCResponse {
  id: number;
  ioc_type: string;
  value: string;
  source: string;
  severity: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  context: Record<string, unknown>;
  active: boolean;
  feed_id: number | null;
  confidence: number | null;
  expires_at: string | null;
  false_positive: boolean;
  hit_count: number;
  last_hit_at: string | null;
}


// ── Thresholds ──

/** @bridge ThresholdResponse */
export interface ThresholdResponse {
  key: string;
  category: string;
  description: string;
  current_value: number;
  default_value: number;
  type: string;
}


// ── YARA (Phase 15) ──

/** @bridge YaraRuleResponse */
export interface YaraRuleResponse {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  tags: string[];
  match_count: number;
  last_match_at: string | null;
}

/** @bridge YaraScanResultResponse */
export interface YaraScanResultResponse {
  id: number;
  scan_type: string;
  target: string;
  rule_name: string;
  rule_namespace: string | null;
  strings_matched: Array<Record<string, unknown>>;
  meta: Record<string, unknown>;
  severity: string;
  scanned_at: string | null;
  file_hash: string | null;
  file_size: number | null;
  triggered_by: string | null;
}


// ── Memory Scanner (Phase 15) ──

/** @bridge MemoryScanResultResponse */
export interface MemoryScanResultResponse {
  id: number;
  pid: number;
  process_name: string;
  finding_type: string;
  severity: string;
  details: Record<string, unknown>;
  scanned_at: string | null;
}


// ── Sword Protocol (Phase 15) ──

/** @bridge SwordPolicyResponse */
export interface SwordPolicyResponse {
  id: number;
  codename: string;
  name: string;
  description: string | null;
  trigger_type: string;
  trigger_conditions: Record<string, unknown>;
  escalation_chain: Array<{ type: string; target: string; duration?: number }>;
  cooldown_seconds: number;
  rate_limit: Record<string, unknown> | null;
  enabled: boolean;
  requires_confirmation: boolean;
  execution_count: number;
  last_triggered: string | null;
  created_at: string | null;
}

/** @bridge SwordLogResponse */
export interface SwordLogResponse {
  id: number;
  policy_id: number;
  codename: string;
  trigger_event: Record<string, unknown>;
  actions_taken: Array<{ action: string; target: string; status: string }>;
  result: string;
  escalation_level: number;
  executed_at: string | null;
  duration_ms: number | null;
}

/** @bridge SwordStats */
export interface SwordStats {
  total_evaluations: number;
  total_strikes: number;
  total_rate_limited: number;
  total_failed: number;
  last_strike: string | null;
  enabled: boolean;
  lockout: boolean;
  policies_loaded: number;
  recent_executions: Array<Record<string, unknown>>;
}


// ── Overwatch (Phase 15) ──

/** @bridge OverwatchStatus */
export interface OverwatchStatus {
  status: string;
  files_baselined: number;
  tamper_count: number;
  last_check: string | null;
  check_interval_seconds: number;
}

/** @bridge OverwatchIntegrityReport */
export interface OverwatchIntegrityReport {
  status: string;
  tampered: string[];
  missing: string[];
  new: string[];
  total_baselined: number;
  tamper_count_total: number;
  checked_at: string;
}
