"""Rule-Based Threat Detection Engine — immediate detection without ML training.

Provides a library of built-in detection rules covering MITRE ATT&CK categories:
credential access, lateral movement, persistence, execution, defense evasion,
and exfiltration.  Each rule is a callable condition evaluated against incoming
events from the process analyzer and event-log monitor.
"""

from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable

from ..utils.logging import get_logger

logger = get_logger("ai.rule_engine")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    """A single threat-detection rule."""

    id: str
    name: str
    description: str
    severity: str  # critical / high / medium / low
    category: str  # lateral_movement / credential_access / persistence / execution / defense_evasion / exfiltration
    condition: Callable[[dict], bool]
    enabled: bool = True


@dataclass
class RuleMatch:
    """Record of a rule that matched an event."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    timestamp: str
    matched_event: dict
    explanation: str


# ---------------------------------------------------------------------------
# Built-in rule conditions
# ---------------------------------------------------------------------------

# -- Credential Access -------------------------------------------------------

_CREDENTIAL_TOOLS = {"mimikatz", "lazagne", "procdump", "pwdump", "gsecdump", "wce", "secretsdump"}


def _r001_credential_tool(event: dict) -> bool:
    """Detect well-known credential-dumping tools by process name."""
    name = (event.get("name") or "").lower()
    exe = (event.get("exe") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    for tool in _CREDENTIAL_TOOLS:
        if tool in name or tool in exe or tool in cmdline:
            return True
    return False


def _r002_lsass_access(event: dict) -> bool:
    """Detect processes accessing LSASS memory."""
    details = (event.get("details") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    target = (event.get("target_process") or "").lower()
    if "lsass" in target or "lsass.exe" in details or "lsass.exe" in cmdline:
        return True
    # Event-log style: event_id 10 (process access) referencing lsass
    if event.get("event_id") == 10 and "lsass" in details:
        return True
    return False


def _r003_sam_access(event: dict) -> bool:
    """Detect SAM database file access."""
    details = (event.get("details") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    file_path = (event.get("file_path") or "").lower()
    sam_path = r"c:\windows\system32\config\sam"
    return sam_path in details or sam_path in cmdline or sam_path in file_path


# -- Lateral Movement --------------------------------------------------------

def _r004_psexec_usage(event: dict) -> bool:
    """Detect PsExec execution or service."""
    name = (event.get("name") or "").lower()
    exe = (event.get("exe") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    indicators = ("psexec", "psexesvc")
    for indicator in indicators:
        if indicator in name or indicator in exe or indicator in cmdline or indicator in details:
            return True
    return False


def _r005_wmi_remote(event: dict) -> bool:
    """Detect WMI remote execution (wmic /node:)."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "wmic" in name or "wmic" in cmdline:
        if "/node:" in cmdline:
            return True
    return False


def _r006_rdp_unusual(event: dict) -> bool:
    """Detect RDP connection from unusual source."""
    event_type = (event.get("event_type") or "").lower()
    event_id = event.get("event_id")
    details = (event.get("details") or "").lower()
    # Windows Security event 4624 logon type 10 = RDP
    if event_id == 4624 and "logon type:            10" in details:
        return True
    if event_type == "rdp_connection":
        return True
    # Event log: TerminalServices-LocalSessionManager event 21 (session logon)
    if event_id == 21 and "terminalsession" in details:
        return True
    return False


# -- Persistence -------------------------------------------------------------

def _r007_new_service(event: dict) -> bool:
    """Detect new service creation."""
    event_id = event.get("event_id")
    details = (event.get("details") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    # System event 7045 = new service installed
    if event_id == 7045:
        return True
    if "sc create" in cmdline or "new-service" in cmdline:
        return True
    if "service installed" in details:
        return True
    return False


def _r008_registry_run_key(event: dict) -> bool:
    """Detect Registry Run key modification for persistence."""
    details = (event.get("details") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    event_type = (event.get("event_type") or "").lower()
    run_key = r"software\microsoft\windows\currentversion\run"
    if run_key in details or run_key in cmdline:
        return True
    if event_type == "registry_modification" and "run" in details:
        return True
    return False


def _r009_scheduled_task(event: dict) -> bool:
    """Detect scheduled task creation."""
    name = (event.get("name") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    if "schtasks" in name or "schtasks" in cmdline:
        if "/create" in cmdline:
            return True
    if "taskschd" in name or "taskschd" in cmdline or "taskschd" in details:
        return True
    # Event ID 4698 = scheduled task created
    if event.get("event_id") == 4698:
        return True
    return False


# -- Execution ---------------------------------------------------------------

def _r010_powershell_encoded(event: dict) -> bool:
    """Detect PowerShell with encoded commands."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "powershell" in name or "pwsh" in name or "powershell" in cmdline:
        if "-enc " in cmdline or "-encodedcommand" in cmdline or "-ec " in cmdline:
            return True
    return False


_OFFICE_PARENTS = {"winword", "excel", "outlook", "powerpnt", "msaccess", "mspub"}


def _r011_cmd_from_office(event: dict) -> bool:
    """Detect cmd.exe spawned by an Office application."""
    name = (event.get("name") or "").lower()
    parent_name = (event.get("parent_name") or "").lower()
    if "cmd" not in name:
        return False
    for office in _OFFICE_PARENTS:
        if office in parent_name:
            return True
    return False


def _r012_script_from_temp(event: dict) -> bool:
    """Detect script execution from temp directory."""
    name = (event.get("name") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    exe = (event.get("exe") or "").lower()
    is_script_host = "wscript" in name or "cscript" in name or "wscript" in exe or "cscript" in exe
    if not is_script_host:
        return False
    temp_indicators = ("\\temp\\", "\\tmp\\", "%temp%", "%tmp%", "\\appdata\\local\\temp")
    for indicator in temp_indicators:
        if indicator in cmdline.lower() or indicator in exe.lower():
            return True
    return False


# -- Defense Evasion ---------------------------------------------------------

def _r013_event_log_cleared(event: dict) -> bool:
    """Detect event log clearing."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    if "wevtutil" in cmdline and " cl " in cmdline:
        return True
    if "clear-eventlog" in cmdline:
        return True
    # Security event 1102 = audit log cleared
    if event.get("event_id") == 1102:
        return True
    if "event log" in details and "cleared" in details:
        return True
    return False


def _r014_defender_disabled(event: dict) -> bool:
    """Detect Windows Defender being disabled."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    if "set-mppreference" in cmdline and "disablerealtimemonitoring" in cmdline:
        return True
    if "disablerealtimemonitoring" in details:
        return True
    # Registry key for defender real-time protection
    if "disableantispyware" in cmdline or "disableantispyware" in details:
        return True
    return False


def _r015_firewall_modification(event: dict) -> bool:
    """Detect firewall rule modification by non-system process."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    details = (event.get("details") or "").lower()
    is_firewall_cmd = (
        ("netsh" in name or "netsh" in cmdline)
        and ("advfirewall" in cmdline or "firewall" in cmdline)
    )
    if not is_firewall_cmd:
        # Also catch PowerShell firewall cmdlets
        if "new-netfirewallrule" in cmdline or "set-netfirewallrule" in cmdline:
            is_firewall_cmd = True
    if not is_firewall_cmd:
        return False
    # Exclude system processes
    exe = (event.get("exe") or "").lower()
    if "system32" in exe and "svchost" in name:
        return False
    return True


# -- Exfiltration ------------------------------------------------------------

_EXFIL_BYTES_THRESHOLD = 50 * 1024 * 1024  # 50 MB


def _r016_large_outbound(event: dict) -> bool:
    """Detect large outbound data transfer to a single external IP."""
    bytes_sent = event.get("bytes_sent", 0) or 0
    event_type = (event.get("event_type") or "").lower()
    if bytes_sent >= _EXFIL_BYTES_THRESHOLD:
        return True
    # Also check details for transfer size
    if event_type == "network_transfer":
        transfer_size = event.get("transfer_size", 0) or 0
        if transfer_size >= _EXFIL_BYTES_THRESHOLD:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_BUILTIN_RULES: list[DetectionRule] = [
    # Credential Access
    DetectionRule(
        id="R001",
        name="Credential Dumping Tool Detected",
        description="A known credential-dumping tool (mimikatz, lazagne, procdump, pwdump, gsecdump, wce, secretsdump) was detected running on the system.",
        severity="critical",
        category="credential_access",
        condition=_r001_credential_tool,
    ),
    DetectionRule(
        id="R002",
        name="LSASS Memory Access",
        description="A process was detected accessing LSASS memory, which is commonly used to extract credentials from Windows systems.",
        severity="critical",
        category="credential_access",
        condition=_r002_lsass_access,
    ),
    DetectionRule(
        id="R003",
        name="SAM Database Access",
        description="Direct access to the SAM database file was detected, indicating an attempt to extract local account password hashes.",
        severity="high",
        category="credential_access",
        condition=_r003_sam_access,
    ),

    # Lateral Movement
    DetectionRule(
        id="R004",
        name="PsExec Usage Detected",
        description="PsExec or its service component PSEXESVC was detected, commonly used for lateral movement across the network.",
        severity="high",
        category="lateral_movement",
        condition=_r004_psexec_usage,
    ),
    DetectionRule(
        id="R005",
        name="WMI Remote Execution",
        description="WMIC was invoked with a /node: parameter, indicating remote command execution via WMI.",
        severity="high",
        category="lateral_movement",
        condition=_r005_wmi_remote,
    ),
    DetectionRule(
        id="R006",
        name="RDP Connection from Unusual Source",
        description="An RDP session was established from a source that may not be an authorized administrator.",
        severity="medium",
        category="lateral_movement",
        condition=_r006_rdp_unusual,
    ),

    # Persistence
    DetectionRule(
        id="R007",
        name="New Service Created",
        description="A new Windows service was installed, which can be used as a persistence mechanism by attackers.",
        severity="medium",
        category="persistence",
        condition=_r007_new_service,
    ),
    DetectionRule(
        id="R008",
        name="Registry Run Key Modification",
        description="A modification to the Windows Registry Run key was detected, commonly used for persistence across reboots.",
        severity="high",
        category="persistence",
        condition=_r008_registry_run_key,
    ),
    DetectionRule(
        id="R009",
        name="Scheduled Task Created",
        description="A new scheduled task was created via schtasks or Task Scheduler, which can be abused for persistence or execution.",
        severity="medium",
        category="persistence",
        condition=_r009_scheduled_task,
    ),

    # Execution
    DetectionRule(
        id="R010",
        name="PowerShell Encoded Command",
        description="PowerShell was launched with an encoded command parameter, frequently used to obfuscate malicious scripts.",
        severity="high",
        category="execution",
        condition=_r010_powershell_encoded,
    ),
    DetectionRule(
        id="R011",
        name="CMD Spawned from Office Application",
        description="A command prompt was spawned by a Microsoft Office process, a common indicator of macro-based malware execution.",
        severity="critical",
        category="execution",
        condition=_r011_cmd_from_office,
    ),
    DetectionRule(
        id="R012",
        name="Script Execution from Temp Directory",
        description="A Windows script host (wscript/cscript) executed a script from a temporary directory, often seen in malware droppers.",
        severity="high",
        category="execution",
        condition=_r012_script_from_temp,
    ),

    # Defense Evasion
    DetectionRule(
        id="R013",
        name="Event Log Cleared",
        description="Windows event logs were cleared, a common tactic to remove evidence of an intrusion.",
        severity="critical",
        category="defense_evasion",
        condition=_r013_event_log_cleared,
    ),
    DetectionRule(
        id="R014",
        name="Windows Defender Disabled",
        description="Windows Defender real-time monitoring was disabled, removing a critical layer of endpoint protection.",
        severity="critical",
        category="defense_evasion",
        condition=_r014_defender_disabled,
    ),
    DetectionRule(
        id="R015",
        name="Firewall Rule Modification",
        description="A non-system process modified Windows Firewall rules, potentially opening access for an attacker.",
        severity="high",
        category="defense_evasion",
        condition=_r015_firewall_modification,
    ),

    # Exfiltration
    DetectionRule(
        id="R016",
        name="Large Outbound Data Transfer",
        description="A large volume of data (>50 MB) was sent to a single external IP, which may indicate data exfiltration.",
        severity="high",
        category="exfiltration",
        condition=_r016_large_outbound,
    ),
]


# ---------------------------------------------------------------------------
# Explanation generators
# ---------------------------------------------------------------------------

_EXPLANATIONS: dict[str, Callable[[dict], str]] = {
    "R001": lambda e: f"Credential tool detected: process '{e.get('name', 'unknown')}' with command line '{(e.get('cmdline') or '')[:120]}'",
    "R002": lambda e: f"LSASS memory access by process '{e.get('name', 'unknown')}' (PID {e.get('pid', '?')})",
    "R003": lambda e: f"SAM database access detected in '{e.get('name', 'unknown')}' targeting {e.get('file_path', e.get('details', 'SAM')[:80])}",
    "R004": lambda e: f"PsExec activity: '{e.get('name', 'unknown')}' with cmdline '{(e.get('cmdline') or '')[:120]}'",
    "R005": lambda e: f"WMI remote execution: '{(e.get('cmdline') or '')[:120]}'",
    "R006": lambda e: f"RDP session detected (event_id={e.get('event_id', '?')}): {(e.get('details') or '')[:100]}",
    "R007": lambda e: f"New service created: event_id={e.get('event_id', '?')}, cmdline='{(e.get('cmdline') or '')[:100]}'",
    "R008": lambda e: f"Registry Run key modified: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R009": lambda e: f"Scheduled task created by '{e.get('name', 'unknown')}': '{(e.get('cmdline') or '')[:120]}'",
    "R010": lambda e: f"Encoded PowerShell command: '{(e.get('cmdline') or '')[:120]}'",
    "R011": lambda e: f"CMD spawned from Office app '{e.get('parent_name', 'unknown')}' (parent PID {e.get('ppid', '?')})",
    "R012": lambda e: f"Script from temp dir: '{e.get('name', 'unknown')}' executing '{(e.get('cmdline') or '')[:120]}'",
    "R013": lambda e: f"Event log cleared: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R014": lambda e: f"Defender disabled: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R015": lambda e: f"Firewall rule modified by '{e.get('name', 'unknown')}': '{(e.get('cmdline') or '')[:120]}'",
    "R016": lambda e: f"Large outbound transfer: {e.get('bytes_sent', e.get('transfer_size', 0))} bytes to {e.get('remote_addr', 'unknown')}",
}


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Rule-based threat detection engine.

    Evaluates incoming events against a library of detection rules and
    maintains a rolling window of recent matches for querying.
    """

    def __init__(self) -> None:
        self._rules: list[DetectionRule] = list(_BUILTIN_RULES)
        self._matches: deque[RuleMatch] = deque(maxlen=1000)
        logger.info("rule_engine_initialized", rule_count=len(self._rules))

    # -- Evaluation ----------------------------------------------------------

    def evaluate(self, event: dict) -> list[RuleMatch]:
        """Evaluate all enabled rules against a single event.

        Args:
            event: Dict with fields from process analyzer or event-log
                   monitor (name, exe, cmdline, event_id, details, etc.).

        Returns:
            List of RuleMatch objects for rules that matched.
        """
        matches: list[RuleMatch] = []
        now = datetime.now(timezone.utc).isoformat()

        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if rule.condition(event):
                    explanation_fn = _EXPLANATIONS.get(rule.id)
                    explanation = explanation_fn(event) if explanation_fn else f"Rule {rule.id} matched"

                    match = RuleMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        timestamp=now,
                        matched_event=event,
                        explanation=explanation,
                    )
                    matches.append(match)
                    self._matches.appendleft(match)
                    logger.warning(
                        "rule_match",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        explanation=explanation,
                    )
            except Exception as exc:
                logger.error("rule_evaluation_error", rule_id=rule.id, error=str(exc))

        return matches

    # -- Query ---------------------------------------------------------------

    def get_rules(self) -> list[dict]:
        """Return all rules as serializable dicts."""
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "category": r.category,
                "enabled": r.enabled,
            }
            for r in self._rules
        ]

    def get_matches(self, limit: int = 100) -> list[dict]:
        """Return recent rule matches as serializable dicts.

        Args:
            limit: Maximum number of matches to return (default 100).
        """
        results = []
        for match in self._matches:
            if len(results) >= limit:
                break
            results.append(asdict(match))
        return results

    def get_stats(self) -> dict:
        """Return match counts grouped by severity and category."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for match in self._matches:
            by_severity[match.severity] = by_severity.get(match.severity, 0) + 1
            by_category[match.category] = by_category.get(match.category, 0) + 1

        return {
            "total_matches": len(self._matches),
            "by_severity": by_severity,
            "by_category": by_category,
            "rules_enabled": sum(1 for r in self._rules if r.enabled),
            "rules_total": len(self._rules),
        }
