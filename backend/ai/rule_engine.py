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

# Default threshold; overridden at runtime via RuleEngine.exfil_bytes_threshold
_EXFIL_BYTES_THRESHOLD = 10_000_000  # 10 MB (configurable via config.exfil_bytes_threshold)


def _r016_large_outbound(event: dict) -> bool:
    """Detect large outbound data transfer to a single external IP."""
    threshold = RuleEngine.exfil_bytes_threshold
    bytes_sent = event.get("bytes_sent", 0) or 0
    event_type = (event.get("event_type") or "").lower()
    if bytes_sent >= threshold:
        return True
    # Also check details for transfer size
    if event_type == "network_transfer":
        transfer_size = event.get("transfer_size", 0) or 0
        if transfer_size >= threshold:
            return True
    return False


# -- LOLBin Abuse (Phase 12 Track 1) ----------------------------------------

def _r017_certutil_download(event: dict) -> bool:
    """Detect certutil used for download or decode operations."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "certutil" not in name and "certutil" not in cmdline:
        return False
    return any(flag in cmdline for flag in ("-urlcache", "-decode", "-encode", "-decodehex"))


def _r018_mshta_execution(event: dict) -> bool:
    """Detect mshta executing URLs or script protocols."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "mshta" not in name and "mshta" not in cmdline:
        return False
    return any(proto in cmdline for proto in ("http://", "https://", "javascript:", "vbscript:"))


_RUNDLL32_SAFE_DLLS = {"shell32", "user32", "kernel32", "advapi32", "ole32", "comctl32", "shlwapi"}


def _r019_rundll32_unusual(event: dict) -> bool:
    """Detect rundll32 loading a DLL not in the safe whitelist."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "rundll32" not in name and "rundll32" not in cmdline:
        return False
    for safe in _RUNDLL32_SAFE_DLLS:
        if safe in cmdline:
            return False
    return len(cmdline.split()) > 1  # has arguments beyond just rundll32


def _r020_regsvr32_scriptlet(event: dict) -> bool:
    """Detect regsvr32 Squiblydoo / scriptlet loading."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "regsvr32" not in name and "regsvr32" not in cmdline:
        return False
    return any(indicator in cmdline for indicator in ("/s /n /u", "/i:", "scrobj.dll", "http://", "https://"))


def _r021_wmic_process_create(event: dict) -> bool:
    """Detect WMIC process call create for local execution."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "wmic" not in name and "wmic" not in cmdline:
        return False
    return "process call create" in cmdline or "process" in cmdline and "create" in cmdline


def _r022_bitsadmin_transfer(event: dict) -> bool:
    """Detect BITSAdmin used for file transfer/download."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "bitsadmin" not in name and "bitsadmin" not in cmdline:
        return False
    return any(flag in cmdline for flag in ("/transfer", "/create", "/addfile"))


def _r023_msiexec_remote(event: dict) -> bool:
    """Detect msiexec installing from remote URL in quiet mode."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "msiexec" not in name and "msiexec" not in cmdline:
        return False
    has_url = "http://" in cmdline or "https://" in cmdline
    has_quiet = "/q" in cmdline or "/quiet" in cmdline
    return has_url and has_quiet


def _r024_msbuild_inline(event: dict) -> bool:
    """Detect MSBuild executing inline tasks from suspicious locations."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "msbuild" not in name and "msbuild" not in cmdline:
        return False
    suspicious_paths = ("\\temp\\", "\\tmp\\", "\\appdata\\", "%temp%", "%appdata%")
    has_project = ".xml" in cmdline or ".csproj" in cmdline
    from_suspicious = any(p in cmdline for p in suspicious_paths)
    return has_project and from_suspicious


def _r025_powershell_download_cradle(event: dict) -> bool:
    """Detect PowerShell download cradle patterns."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "powershell" not in name and "pwsh" not in name and "powershell" not in cmdline:
        return False
    cradles = ("downloadstring", "downloadfile", "iwr ", "invoke-webrequest",
               "net.webclient", "start-bitstransfer", "wget ", "curl ")
    return any(c in cmdline for c in cradles)


def _r026_amsi_bypass(event: dict) -> bool:
    """Detect AMSI bypass attempts."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    combined = cmdline + " " + details
    return any(indicator in combined for indicator in ("amsiutils", "amsiinitfailed", "amsi.dll", "amsiscanbuffer", "amsiscanstring"))


# -- Privilege Escalation (Phase 12 Track 3) ---------------------------------

def _r027_uac_bypass_fodhelper(event: dict) -> bool:
    """Detect UAC bypass via fodhelper.exe."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    name = (event.get("name") or "").lower()
    if "fodhelper" in name or "fodhelper" in cmdline:
        return True
    reg_path = r"software\classes\ms-settings\shell\open\command"
    return reg_path in cmdline or reg_path in details


def _r028_uac_bypass_eventvwr(event: dict) -> bool:
    """Detect UAC bypass via eventvwr.exe registry hijack."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    reg_path = r"software\classes\mscfile\shell\open\command"
    if reg_path in cmdline or reg_path in details:
        return True
    parent_name = (event.get("parent_name") or "").lower()
    name = (event.get("name") or "").lower()
    return "eventvwr" in parent_name and ("cmd" in name or "powershell" in name)


def _r029_token_manipulation(event: dict) -> bool:
    """Detect token impersonation / manipulation."""
    cmdline = (event.get("cmdline") or "").lower()
    raw_details = event.get("details") or ""
    details_str = str(raw_details).lower() if not isinstance(raw_details, str) else raw_details.lower()
    event_id = event.get("event_id")
    if event_id == 4672:
        # Skip routine service accounts — SYSTEM, LOCAL SERVICE, NETWORK SERVICE
        # always receive special privileges on logon.
        if isinstance(raw_details, dict):
            sid = raw_details.get("Security ID", "")
            account = raw_details.get("Account Name", "").upper()
        else:
            sid = ""
            account = ""
        routine_sids = ("S-1-5-18", "S-1-5-19", "S-1-5-20")
        routine_accounts = ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
        if sid in routine_sids or account in routine_accounts:
            return False
        return True
    indicators = ("impersonateloggedonuser", "duplicatetokenex", "setthreadtoken",
                  "adjusttokenprivileges", "sedebugprivilege", "seimpersonateprivilege")
    combined = cmdline + " " + details_str
    return any(i in combined for i in indicators)


def _r030_runas_saved_creds(event: dict) -> bool:
    """Detect runas with saved credentials."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if "runas" not in name and "runas" not in cmdline:
        return False
    return "/savecred" in cmdline or "/netonly" in cmdline


# -- Reconnaissance (Phase 12 Track 3) --------------------------------------

def _r031_user_group_enum(event: dict) -> bool:
    """Detect user/group enumeration commands."""
    cmdline = (event.get("cmdline") or "").lower()
    enum_cmds = ("net user", "net localgroup", "net group", "whoami /priv",
                 "whoami /groups", "qwinsta", "query user")
    return any(cmd in cmdline for cmd in enum_cmds)


def _r032_domain_trust_enum(event: dict) -> bool:
    """Detect domain trust discovery and enumeration."""
    cmdline = (event.get("cmdline") or "").lower()
    indicators = ("nltest /domain_trusts", "nltest /dclist", "dsquery trust",
                  "get-adtrust", "get-addomain", "get-adforest",
                  "[system.directoryservices.activedirectory")
    return any(i in cmdline for i in indicators)


def _r033_system_discovery(event: dict) -> bool:
    """Detect system discovery / enumeration commands."""
    cmdline = (event.get("cmdline") or "").lower()
    discovery = ("systeminfo", "ipconfig /all", "arp -a", "route print",
                 "netstat -ano", "tasklist /v", "wmic os get", "wmic computersystem")
    return any(d in cmdline for d in discovery)


# -- Impact (Phase 12 Track 3) -----------------------------------------------

def _r034_shadow_copy_deletion(event: dict) -> bool:
    """Detect shadow copy / backup deletion (ransomware indicator)."""
    cmdline = (event.get("cmdline") or "").lower()
    indicators = ("vssadmin delete shadows", "wmic shadowcopy delete",
                  "bcdedit /set {default} recoveryenabled no",
                  "bcdedit /set recoveryenabled no",
                  "wbadmin delete catalog", "vssadmin resize shadowstorage")
    return any(i in cmdline for i in indicators)


def _r035_security_service_stop(event: dict) -> bool:
    """Detect mass stopping of security services."""
    cmdline = (event.get("cmdline") or "").lower()
    security_services = ("windefend", "mpssvc", "wscsvc", "securityhealthservice",
                         "sense", "senseir", "wuauserv", "bits", "vss",
                         "sql", "exchange", "mssql")
    if "net stop" in cmdline or "sc stop" in cmdline or "stop-service" in cmdline:
        return any(svc in cmdline for svc in security_services)
    return False


def _r036_disk_wipe(event: dict) -> bool:
    """Detect disk wipe / destruction commands."""
    cmdline = (event.get("cmdline") or "").lower()
    indicators = ("format c:", "cipher /w:", "sdelete", "diskpart",
                  "clean all", "dd if=/dev/zero", "bootrec /fixmbr")
    return any(i in cmdline for i in indicators)


# -- Collection (Phase 12 Track 3) -------------------------------------------

def _r037_browser_credential_access(event: dict) -> bool:
    """Detect browser credential file access."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    file_path = (event.get("file_path") or "").lower()
    combined = cmdline + " " + details + " " + file_path
    credential_paths = ("login data", "logins.json", "key3.db", "key4.db",
                        "cookies.sqlite", "web data", "\\vault\\", "credential")
    return any(p in combined for p in credential_paths)


def _r038_keylogger_indicators(event: dict) -> bool:
    """Detect keylogger-like behavior."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    combined = cmdline + " " + details
    indicators = ("getasynckeystate", "setwindowshookex", "wh_keyboard",
                  "rawinputdevice", "keylog", "keystroke")
    return any(i in combined for i in indicators)


# -- Command and Control (Phase 12 Track 3) ----------------------------------

def _r039_dns_tunneling(event: dict) -> bool:
    """Detect DNS tunneling patterns (high-entropy long subdomains)."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    dns_query = (event.get("dns_query") or "").lower()
    combined = cmdline + " " + details + " " + dns_query
    indicators = ("nslookup -type=txt", "resolve-dnsname -type txt",
                  "dns-over-https", "doh.", "dns2tcp", "iodine", "dnscat")
    if any(i in combined for i in indicators):
        return True
    if dns_query and len(dns_query) > 80:
        return True
    return False


def _r042_thinkphp_rce(event: dict) -> bool:
    """Detect ThinkPHP remote code execution exploitation (CVE-2018-20062, CVE-2019-9082)."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    url = (event.get("url") or "").lower()
    combined = cmdline + " " + details + " " + url
    indicators = ("invokefunction", "call_user_func_array", "think\\app",
                  "think\\container", "s=/index/\\think", "thinkphp",
                  "nonecms", "think\\invoker")
    return any(i in combined for i in indicators)


def _r041_ransomware_mass_rename(event: dict) -> bool:
    """Detect mass file rename / extension change patterns (ransomware indicator)."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    combined = cmdline + " " + details
    # Ransomware file extension indicators
    ransom_extensions = (".encrypted", ".locked", ".crypt", ".enc", ".ransom",
                         ".lockbit", ".blackcat", ".alphv", ".wncry", ".wcry",
                         ".cerber", ".locky", ".zepto", ".thor", ".aesir")
    if any(ext in combined for ext in ransom_extensions):
        return True
    # Mass rename commands
    mass_rename_indicators = ("for %", "forfiles", "ren \"", "rename ",
                               "mass rename", "rapid extension change",
                               "mass encryption", "encrypt")
    return any(i in combined for i in mass_rename_indicators)


# -- Phase 13: Additional MITRE ATT&CK Rules --------------------------------

def _r043_account_manipulation(event: dict) -> bool:
    """Detect account manipulation — adding users to privileged groups, password resets."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    event_id = event.get("event_id")
    # net localgroup administrators /add, net user /add
    if "net " in cmdline and ("/add" in cmdline or "localgroup" in cmdline):
        return True
    # Windows Security Event IDs for account changes
    if event_id in (4720, 4722, 4728, 4732, 4756):  # user created, enabled, added to group
        return True
    if "add-localgroupmember" in cmdline or "add-adgroupmember" in cmdline:
        return True
    return False


def _r044_process_masquerading(event: dict) -> bool:
    """Detect process masquerading — executables mimicking legitimate system process names."""
    name = (event.get("name") or "").lower()
    exe = (event.get("exe") or "").lower()
    # System processes that should only run from System32
    system_procs = {
        "svchost.exe": r"c:\windows\system32\svchost.exe",
        "csrss.exe": r"c:\windows\system32\csrss.exe",
        "lsass.exe": r"c:\windows\system32\lsass.exe",
        "services.exe": r"c:\windows\system32\services.exe",
        "smss.exe": r"c:\windows\system32\smss.exe",
        "wininit.exe": r"c:\windows\system32\wininit.exe",
        "winlogon.exe": r"c:\windows\system32\winlogon.exe",
    }
    for proc_name, expected_path in system_procs.items():
        if name == proc_name and exe and expected_path not in exe:
            return True
    # Lookalike names: svch0st, scvhost, etc.
    lookalikes = ["svch0st", "scvhost", "csvhost", "lssas", "lsas", "csrs"]
    for lookalike in lookalikes:
        if lookalike in name:
            return True
    return False


def _r045_archive_staging(event: dict) -> bool:
    """Detect staging data in archives for exfiltration."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    # Compression tools used for staging
    if any(tool in name for tool in ["7z", "7za", "rar", "winrar"]):
        if any(flag in cmdline for flag in [" a ", "-r", "*.doc", "*.pdf", "*.xls", "*.pst"]):
            return True
    # PowerShell Compress-Archive
    if "compress-archive" in cmdline:
        return True
    # makecab for data staging
    if "makecab" in cmdline:
        return True
    return False


def _r046_screen_capture(event: dict) -> bool:
    """Detect screen capture tools and techniques."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    if any(tool in name for tool in ["screenshot", "snagit", "greenshot", "sharex"]):
        return True
    # PowerShell screen capture
    if "system.drawing.bitmap" in cmdline and "copyfroms" in cmdline:
        return True
    if "get-screenshot" in cmdline or "capture-screen" in cmdline:
        return True
    return False


def _r047_email_collection(event: dict) -> bool:
    """Detect email collection from local clients or Exchange."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    file_path = (event.get("file_path") or "").lower()
    # PST/OST file access
    if any(ext in file_path for ext in [".pst", ".ost"]):
        return True
    # PowerShell accessing Outlook COM
    if "outlook.application" in cmdline or "new-object -comobject outlook" in cmdline:
        return True
    # Exchange cmdlets
    if "get-mailbox" in cmdline or "search-mailbox" in cmdline or "new-mailboxexportrequest" in cmdline:
        return True
    return False


def _r048_dll_sideloading(event: dict) -> bool:
    """Detect DLL side-loading — loading DLLs from non-standard paths."""
    details = (event.get("details") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()
    event_id = event.get("event_id")
    # Sysmon DLL load from non-standard location (Event ID 7)
    if event_id == 7:
        if "signed" in details and "false" in details:
            return True
        # DLL loaded from temp or user directories
        if any(path in details for path in ["\\temp\\", "\\appdata\\", "\\downloads\\"]):
            return True
    # Known side-loading targets
    sideload_targets = ["version.dll", "cryptsp.dll", "wtsapi32.dll", "dbghelp.dll"]
    for target in sideload_targets:
        if target in details and "\\system32\\" not in details:
            return True
    return False


def _r049_wmi_persistence(event: dict) -> bool:
    """Detect WMI event subscription for persistence."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    event_id = event.get("event_id")
    # WMI subscription via wmic or PowerShell
    if "wmic" in cmdline and ("__eventfilter" in cmdline or "__eventconsumer" in cmdline):
        return True
    if "set-wminstance" in cmdline or "register-wmievent" in cmdline:
        return True
    if "__eventfilter" in cmdline and "__filtertoconsumerbinding" in cmdline:
        return True
    # Sysmon WMI events (Event IDs 19, 20, 21)
    if event_id in (19, 20, 21):
        return True
    return False


def _r050_ntds_access(event: dict) -> bool:
    """Detect NTDS.dit access for credential extraction."""
    cmdline = (event.get("cmdline") or "").lower()
    details = (event.get("details") or "").lower()
    file_path = (event.get("file_path") or "").lower()
    # Direct NTDS.dit access
    ntds_path = "ntds.dit"
    if ntds_path in cmdline or ntds_path in details or ntds_path in file_path:
        return True
    # ntdsutil
    if "ntdsutil" in cmdline:
        return True
    # Volume shadow copy + NTDS
    if "vssadmin" in cmdline and "shadow" in cmdline:
        if "ntds" in cmdline:
            return True
    # secretsdump targeting DC
    if "secretsdump" in cmdline:
        return True
    return False


def _r051_notepad_rce(event: dict) -> bool:
    """Detect CVE-2026-20841: Notepad Markdown handler RCE.

    Modern Notepad (11.0.0-11.2509) can execute arbitrary commands when
    a user opens a crafted .md file and clicks an embedded link.  Notepad
    should never spawn child processes — any child of notepad.exe is
    suspicious, especially shells, scripting engines, or LOLBins.
    """
    parent = (event.get("parent_name") or "").lower()
    if "notepad" not in parent:
        return False

    name = (event.get("name") or "").lower()
    exe = (event.get("exe") or "").lower()
    cmdline = (event.get("cmdline") or "").lower()

    # Shells and scripting engines notepad should never launch
    suspicious_children = (
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "bash.exe", "python.exe",
        "conhost.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "msiexec.exe",
    )
    for child in suspicious_children:
        if child in name or child in exe:
            return True

    # Command-line with markdown-exploit indicators
    md_indicators = ("invoke-expression", "iex ", "downloadstring",
                     "start-process", "new-object", "shell.application")
    if any(ind in cmdline for ind in md_indicators):
        return True

    return False


def _r040_known_c2_tools(event: dict) -> bool:
    """Detect known C2 framework and malware family signatures."""
    cmdline = (event.get("cmdline") or "").lower()
    name = (event.get("name") or "").lower()
    details = (event.get("details") or "").lower()
    combined = cmdline + " " + name + " " + details
    c2_and_malware = (
        # C2 frameworks
        "cobaltstrike", "beacon.dll", "beacon.exe", "empire", "meterpreter",
        "sliver", "havoc", "brute ratel", "poshc2",
        "covenant", "merlin", "mythic", "deimosc2",
        # Known malware families
        "emotet", "trickbot", "qakbot", "icedid", "bumblebee",
        "raspberry robin", "asyncrat", "remcos", "njrat", "darkcomet",
        "agenttesla", "formbook", "lokibot", "raccoon", "redline",
    )
    return any(t in combined for t in c2_and_malware)


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

    # LOLBin Abuse (Phase 12)
    DetectionRule(
        id="R017",
        name="Certutil Download/Decode",
        description="Certutil was used with -urlcache, -decode, or -encode flags, commonly abused to download payloads or decode malicious files (T1105).",
        severity="high",
        category="execution",
        condition=_r017_certutil_download,
    ),
    DetectionRule(
        id="R018",
        name="MSHTA URL Execution",
        description="MSHTA was used to execute content from a URL or script protocol, bypassing application whitelisting (T1218.005).",
        severity="critical",
        category="defense_evasion",
        condition=_r018_mshta_execution,
    ),
    DetectionRule(
        id="R019",
        name="Rundll32 Unusual DLL",
        description="Rundll32 loaded a DLL not in the standard system whitelist, potentially executing malicious code (T1218.011).",
        severity="high",
        category="defense_evasion",
        condition=_r019_rundll32_unusual,
    ),
    DetectionRule(
        id="R020",
        name="Regsvr32 Scriptlet Load",
        description="Regsvr32 was used with scriptlet loading parameters (Squiblydoo attack), bypassing application whitelisting (T1218.010).",
        severity="critical",
        category="defense_evasion",
        condition=_r020_regsvr32_scriptlet,
    ),
    DetectionRule(
        id="R021",
        name="WMIC Process Create",
        description="WMIC was used with 'process call create' to spawn a new process, a common execution technique (T1047).",
        severity="high",
        category="execution",
        condition=_r021_wmic_process_create,
    ),
    DetectionRule(
        id="R022",
        name="BITSAdmin File Transfer",
        description="BITSAdmin was used with transfer/create/addfile parameters, commonly abused for stealthy file downloads (T1197).",
        severity="high",
        category="persistence",
        condition=_r022_bitsadmin_transfer,
    ),
    DetectionRule(
        id="R023",
        name="MSIExec Remote Install",
        description="MSIExec was used to install a package from a remote URL in quiet mode, bypassing user interaction (T1218.007).",
        severity="high",
        category="defense_evasion",
        condition=_r023_msiexec_remote,
    ),
    DetectionRule(
        id="R024",
        name="MSBuild Inline Task Execution",
        description="MSBuild was used to execute inline tasks from XML/CSPROJ files in temp/appdata directories (T1127.001).",
        severity="high",
        category="defense_evasion",
        condition=_r024_msbuild_inline,
    ),
    DetectionRule(
        id="R025",
        name="PowerShell Download Cradle",
        description="PowerShell used a download cradle pattern (DownloadString, IWR, Net.WebClient) to fetch remote content (T1059.001).",
        severity="high",
        category="execution",
        condition=_r025_powershell_download_cradle,
    ),
    DetectionRule(
        id="R026",
        name="AMSI Bypass Attempt",
        description="An attempt to bypass the Antimalware Scan Interface (AMSI) was detected, disabling script-level malware scanning (T1562.001).",
        severity="critical",
        category="defense_evasion",
        condition=_r026_amsi_bypass,
    ),

    # Privilege Escalation (Phase 12)
    DetectionRule(
        id="R027",
        name="UAC Bypass via Fodhelper",
        description="A UAC bypass attempt via fodhelper.exe registry hijack was detected, allowing elevation without a UAC prompt.",
        severity="critical",
        category="privilege_escalation",
        condition=_r027_uac_bypass_fodhelper,
    ),
    DetectionRule(
        id="R028",
        name="UAC Bypass via Event Viewer",
        description="A UAC bypass attempt via eventvwr.exe mscfile handler hijack was detected.",
        severity="critical",
        category="privilege_escalation",
        condition=_r028_uac_bypass_eventvwr,
    ),
    DetectionRule(
        id="R029",
        name="Token Manipulation",
        description="Token impersonation or privilege manipulation was detected, indicating potential privilege escalation.",
        severity="critical",
        category="privilege_escalation",
        condition=_r029_token_manipulation,
    ),
    DetectionRule(
        id="R030",
        name="Runas with Saved Credentials",
        description="The runas command was used with /savecred or /netonly flags, potentially abusing stored credentials for escalation.",
        severity="high",
        category="privilege_escalation",
        condition=_r030_runas_saved_creds,
    ),

    # Reconnaissance (Phase 12)
    DetectionRule(
        id="R031",
        name="User/Group Enumeration",
        description="User or group enumeration commands were detected (net user, whoami /priv, etc.), common in early-stage reconnaissance.",
        severity="medium",
        category="reconnaissance",
        condition=_r031_user_group_enum,
    ),
    DetectionRule(
        id="R032",
        name="Domain Trust Enumeration",
        description="Domain trust discovery tools were detected (nltest, dsquery, Get-ADTrust), indicating Active Directory reconnaissance.",
        severity="high",
        category="reconnaissance",
        condition=_r032_domain_trust_enum,
    ),
    DetectionRule(
        id="R033",
        name="System Discovery Commands",
        description="Multiple system discovery commands were detected (systeminfo, ipconfig, arp, netstat), common in initial access reconnaissance.",
        severity="low",
        category="reconnaissance",
        condition=_r033_system_discovery,
    ),

    # Impact (Phase 12)
    DetectionRule(
        id="R034",
        name="Shadow Copy Deletion",
        description="Shadow copy or backup deletion was detected (vssadmin, wmic shadowcopy, bcdedit), a critical ransomware indicator.",
        severity="critical",
        category="impact",
        condition=_r034_shadow_copy_deletion,
    ),
    DetectionRule(
        id="R035",
        name="Security Service Mass Stop",
        description="Multiple security services were stopped (Defender, firewall, VSS), indicating an attempt to disable defensive tools.",
        severity="critical",
        category="impact",
        condition=_r035_security_service_stop,
    ),
    DetectionRule(
        id="R036",
        name="Disk Wipe Commands",
        description="Disk wiping or destruction commands were detected (format, cipher /w, sdelete), indicating potential data destruction.",
        severity="critical",
        category="impact",
        condition=_r036_disk_wipe,
    ),

    # Collection (Phase 12)
    DetectionRule(
        id="R037",
        name="Browser Credential Access",
        description="Access to browser credential stores was detected (Login Data, logins.json, key3.db), indicating credential harvesting.",
        severity="high",
        category="collection",
        condition=_r037_browser_credential_access,
    ),
    DetectionRule(
        id="R038",
        name="Keylogger Indicators",
        description="Keylogger-like API calls or behavior was detected (GetAsyncKeyState, SetWindowsHookEx, WH_KEYBOARD).",
        severity="critical",
        category="collection",
        condition=_r038_keylogger_indicators,
    ),

    # Command and Control (Phase 12)
    DetectionRule(
        id="R039",
        name="DNS Tunneling Patterns",
        description="DNS tunneling indicators were detected (long subdomain queries, DNS-over-HTTPS tools, known DNS C2 tools).",
        severity="high",
        category="command_and_control",
        condition=_r039_dns_tunneling,
    ),
    DetectionRule(
        id="R040",
        name="Known C2 Tool Signatures",
        description="A known command-and-control framework or malware family was detected (Cobalt Strike, Empire, Meterpreter, Emotet, etc.).",
        severity="critical",
        category="command_and_control",
        condition=_r040_known_c2_tools,
    ),

    # Ransomware (Phase 12 — Smith feedback)
    DetectionRule(
        id="R041",
        name="Ransomware Mass File Rename",
        description="Mass file rename or extension change detected (.encrypted, .locked, .crypt, etc.), a critical ransomware indicator.",
        severity="critical",
        category="impact",
        condition=_r041_ransomware_mass_rename,
    ),

    # Web Exploitation (Bond intel)
    DetectionRule(
        id="R042",
        name="ThinkPHP RCE Exploitation",
        description="ThinkPHP remote code execution attempt detected (CVE-2018-20062, CVE-2019-9082). Attacker using invokefunction/call_user_func_array to execute arbitrary code.",
        severity="critical",
        category="execution",
        condition=_r042_thinkphp_rce,
    ),

    # Phase 13: Additional MITRE ATT&CK Rules
    DetectionRule(
        id="R043",
        name="Account Manipulation",
        description="Account manipulation detected — adding users to privileged groups, enabling accounts, or password resets (T1098).",
        severity="high",
        category="persistence",
        condition=_r043_account_manipulation,
    ),
    DetectionRule(
        id="R044",
        name="Process Masquerading",
        description="Process masquerading detected — an executable is mimicking a legitimate system process name from a non-standard path (T1036).",
        severity="high",
        category="defense_evasion",
        condition=_r044_process_masquerading,
    ),
    DetectionRule(
        id="R045",
        name="Archive Staging for Exfiltration",
        description="Data staging in archives detected — compression tools used to package sensitive files for potential exfiltration (T1560).",
        severity="high",
        category="exfiltration",
        condition=_r045_archive_staging,
    ),
    DetectionRule(
        id="R046",
        name="Screen Capture Activity",
        description="Screen capture tools or techniques detected — potential intelligence collection via screenshots (T1113).",
        severity="medium",
        category="collection",
        condition=_r046_screen_capture,
    ),
    DetectionRule(
        id="R047",
        name="Email Collection",
        description="Email collection activity detected — access to PST/OST files, Outlook COM objects, or Exchange cmdlets (T1114).",
        severity="high",
        category="collection",
        condition=_r047_email_collection,
    ),
    DetectionRule(
        id="R048",
        name="DLL Side-Loading",
        description="DLL side-loading detected — unsigned or non-standard DLLs loaded from temp/appdata/downloads directories (T1574.002).",
        severity="high",
        category="persistence",
        condition=_r048_dll_sideloading,
    ),
    DetectionRule(
        id="R049",
        name="WMI Event Subscription Persistence",
        description="WMI event subscription persistence detected — WMI event filters/consumers used for persistent execution (T1546.003).",
        severity="critical",
        category="persistence",
        condition=_r049_wmi_persistence,
    ),
    DetectionRule(
        id="R050",
        name="NTDS.dit Access",
        description="NTDS.dit credential extraction detected — access to Active Directory database for domain-wide credential theft (T1003.003).",
        severity="critical",
        category="credential_access",
        condition=_r050_ntds_access,
    ),
    DetectionRule(
        id="R051",
        name="Notepad Markdown RCE (CVE-2026-20841)",
        description="Microsoft Notepad Markdown handler RCE detected (CVE-2026-20841). "
                    "Modern Notepad versions 11.0.0-11.2509 execute commands via crafted "
                    ".md file links instead of opening a browser. Notepad spawning a child "
                    "process (shell, scripting engine, or LOLBin) indicates exploitation "
                    "(T1203 — Exploitation for Client Execution).",
        severity="critical",
        category="execution",
        condition=_r051_notepad_rce,
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
    # LOLBin rules
    "R017": lambda e: f"Certutil download/decode: '{(e.get('cmdline') or '')[:120]}'",
    "R018": lambda e: f"MSHTA URL execution: '{(e.get('cmdline') or '')[:120]}'",
    "R019": lambda e: f"Rundll32 unusual DLL: '{(e.get('cmdline') or '')[:120]}'",
    "R020": lambda e: f"Regsvr32 scriptlet load: '{(e.get('cmdline') or '')[:120]}'",
    "R021": lambda e: f"WMIC process create: '{(e.get('cmdline') or '')[:120]}'",
    "R022": lambda e: f"BITSAdmin transfer: '{(e.get('cmdline') or '')[:120]}'",
    "R023": lambda e: f"MSIExec remote install: '{(e.get('cmdline') or '')[:120]}'",
    "R024": lambda e: f"MSBuild inline task: '{(e.get('cmdline') or '')[:120]}'",
    "R025": lambda e: f"PowerShell download cradle: '{(e.get('cmdline') or '')[:120]}'",
    "R026": lambda e: f"AMSI bypass attempt: '{(e.get('cmdline') or '')[:120]}'",
    # Privilege Escalation
    "R027": lambda e: f"UAC bypass via fodhelper: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R028": lambda e: f"UAC bypass via eventvwr: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R029": lambda e: f"Token manipulation: '{(e.get('cmdline') or str(e.get('details') or ''))[:120]}'",
    "R030": lambda e: f"Runas with saved creds: '{(e.get('cmdline') or '')[:120]}'",
    # Reconnaissance
    "R031": lambda e: f"User/group enumeration: '{(e.get('cmdline') or '')[:120]}'",
    "R032": lambda e: f"Domain trust enumeration: '{(e.get('cmdline') or '')[:120]}'",
    "R033": lambda e: f"System discovery: '{(e.get('cmdline') or '')[:120]}'",
    # Impact
    "R034": lambda e: f"Shadow copy deletion: '{(e.get('cmdline') or '')[:120]}'",
    "R035": lambda e: f"Security service stopped: '{(e.get('cmdline') or '')[:120]}'",
    "R036": lambda e: f"Disk wipe command: '{(e.get('cmdline') or '')[:120]}'",
    # Collection
    "R037": lambda e: f"Browser credential access: '{(e.get('cmdline') or e.get('file_path') or '')[:120]}'",
    "R038": lambda e: f"Keylogger indicators: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    # C2
    "R039": lambda e: f"DNS tunneling: '{(e.get('cmdline') or e.get('dns_query') or '')[:120]}'",
    "R040": lambda e: f"C2 tool detected: '{(e.get('cmdline') or e.get('name') or '')[:120]}'",
    "R041": lambda e: f"Ransomware mass rename: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R042": lambda e: f"ThinkPHP RCE exploit (CVE-2018-20062): '{(e.get('cmdline') or e.get('url') or e.get('details') or '')[:120]}'",
    # Phase 13
    "R043": lambda e: f"Account manipulation: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R044": lambda e: f"Process masquerading: '{e.get('name', 'unknown')}' running from '{(e.get('exe') or 'unknown')[:100]}'",
    "R045": lambda e: f"Archive staging for exfiltration: '{(e.get('cmdline') or '')[:120]}'",
    "R046": lambda e: f"Screen capture activity: '{(e.get('cmdline') or e.get('name') or '')[:120]}'",
    "R047": lambda e: f"Email collection: '{(e.get('cmdline') or e.get('file_path') or '')[:120]}'",
    "R048": lambda e: f"DLL side-loading: '{(e.get('details') or e.get('cmdline') or '')[:120]}'",
    "R049": lambda e: f"WMI persistence: '{(e.get('cmdline') or e.get('details') or '')[:120]}'",
    "R050": lambda e: f"NTDS.dit access: '{(e.get('cmdline') or e.get('file_path') or '')[:120]}'",
    "R051": lambda e: f"Notepad RCE (CVE-2026-20841): notepad spawned '{e.get('name', 'unknown')}' with cmdline '{(e.get('cmdline') or '')[:100]}'",
}


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Rule-based threat detection engine.

    Evaluates incoming events against a library of detection rules and
    maintains a rolling window of recent matches for querying.
    """

    # Class-level configurable threshold for exfiltration detection (R016).
    # Updated at runtime from CereberusConfig.exfil_bytes_threshold.
    exfil_bytes_threshold: int = _EXFIL_BYTES_THRESHOLD

    def __init__(self) -> None:
        self._rules: list[DetectionRule] = list(_BUILTIN_RULES)
        self._matches: deque[RuleMatch] = deque(maxlen=1000)
        # Sync class attribute from config if available
        try:
            from ..dependencies import get_app_config
            config = get_app_config()
            RuleEngine.exfil_bytes_threshold = getattr(
                config, "exfil_bytes_threshold", _EXFIL_BYTES_THRESHOLD
            )
        except Exception:
            pass
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
