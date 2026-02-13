"""Event Log Monitor Module — monitors Windows Event Logs for security events.

Polls Windows Security, System, and Sysmon event logs via PowerShell to detect
suspicious activity such as privilege escalation, failed logons, new services,
and account manipulation.
"""

import asyncio
import json
import subprocess
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from .base_module import BaseModule

# Event ID -> (channel, description, default severity)
SECURITY_EVENT_IDS = {
    4688: ("Security", "Process Creation", "low"),
    4672: ("Security", "Privilege Escalation", "low"),
    4624: ("Security", "Logon Success", "low"),
    4625: ("Security", "Logon Failure", "medium"),
    4720: ("Security", "Account Created", "high"),
    4726: ("Security", "Account Deleted", "high"),
    4728: ("Security", "Security Group Member Added", "high"),
    4732: ("Security", "User Added to Group", "high"),
    4756: ("Security", "Universal Group Member Added", "high"),
    4768: ("Security", "Kerberos TGT Requested", "low"),
    4769: ("Security", "Kerberos Service Ticket Requested", "low"),
    4771: ("Security", "Kerberos Pre-Auth Failed", "medium"),
    4776: ("Security", "NTLM Authentication", "low"),
}

SYSTEM_EVENT_IDS = {
    7045: ("System", "Service Installed", "high"),
    7040: ("System", "Service State Changed", "medium"),
}

SYSMON_EVENT_IDS = {
    1: ("Sysmon", "Process Create", "low"),
    2: ("Sysmon", "File Creation Time Changed", "medium"),
    3: ("Sysmon", "Network Connect", "low"),
    5: ("Sysmon", "Process Terminated", "low"),
    7: ("Sysmon", "DLL Loaded", "low"),
    8: ("Sysmon", "CreateRemoteThread", "critical"),
    10: ("Sysmon", "ProcessAccess", "high"),
    11: ("Sysmon", "File Create", "low"),
    12: ("Sysmon", "Registry Object Added/Deleted", "medium"),
    13: ("Sysmon", "Registry Value Set", "medium"),
    15: ("Sysmon", "FileCreateStreamHash (ADS)", "high"),
    17: ("Sysmon", "Named Pipe Created", "medium"),
    18: ("Sysmon", "Named Pipe Connected", "medium"),
    22: ("Sysmon", "DNS Query", "low"),
    23: ("Sysmon", "File Delete", "low"),
    25: ("Sysmon", "Process Tampering", "critical"),
}

# Suspicious parent processes that elevate 4688 severity
SUSPICIOUS_PARENTS = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
}

# Suspicious service names/paths that elevate 7045 severity
SUSPICIOUS_SERVICE_KEYWORDS = {
    "mimikatz", "cobalt", "beacon", "meterpreter", "psexec",
    "temp", "appdata", "downloads",
}


class EventLogMonitor(BaseModule):
    """Monitors Windows Event Logs for security-relevant events."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="event_log_monitor", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 15)
        self._max_events: int = cfg.get("max_events", 500)
        self._enable_sysmon: bool = cfg.get("enable_sysmon", True)
        self._max_events_per_query: int = cfg.get("max_events_per_query", 50)

        # In-memory event storage
        self._events: deque[dict] = deque(maxlen=self._max_events)
        self._poll_task: Optional[asyncio.Task] = None
        self._last_poll: Optional[datetime] = None
        self._sysmon_available: Optional[bool] = None

        # Stats counters
        self._stats: dict = {
            "total_collected": 0,
            "by_event_id": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_channel": {"Security": 0, "System": 0, "Sysmon": 0},
        }

        # Phase 15: EventBus integration + EvtSubscribe
        self._event_bus = None
        self._use_evt_subscribe: bool = cfg.get("use_evt_subscribe", True)
        self._evt_subscriptions: list = []
        self._evt_mode: str = "polling"  # "evtsubscribe" or "polling"

    def set_event_bus(self, bus) -> None:
        """Attach EventBus for real-time event publishing."""
        self._event_bus = bus
        self.logger.info("event_bus_attached")

    async def start(self) -> None:
        """Start the event log monitoring loop."""
        self.running = True
        self.health_status = "running"
        self.logger.info("event_log_monitor_starting")

        # Check Sysmon availability on first start
        if self._enable_sysmon:
            loop = asyncio.get_event_loop()
            self._sysmon_available = await loop.run_in_executor(
                None, self._check_sysmon_available
            )
            if self._sysmon_available:
                self.logger.info("sysmon_detected")
            else:
                self.logger.info("sysmon_not_available")

        # Phase 15: Try EvtSubscribe for real-time push mode
        if self._use_evt_subscribe:
            evt_started = await self._start_evt_subscribe()
            if evt_started:
                self._evt_mode = "evtsubscribe"
                self.logger.info("evt_subscribe_active", mode="push")
            else:
                self.logger.info("evt_subscribe_fallback", mode="polling")

        # Run initial poll (always — catches events before subscription starts)
        await self._collect_events()

        # Start polling loop (also serves as fallback for EvtSubscribe gaps)
        self._poll_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("event_log_monitor_started", mode=self._evt_mode)

    async def stop(self) -> None:
        """Stop the monitoring loop."""
        self.running = False
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        # Stop EvtSubscribe subscriptions
        for sub in self._evt_subscriptions:
            try:
                sub.stop()
            except Exception:
                pass
        self._evt_subscriptions.clear()
        self.health_status = "stopped"
        self.logger.info("event_log_monitor_stopped")

    async def health_check(self) -> dict:
        """Return module health status."""
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "total_events": len(self._events),
                "total_collected": self._stats["total_collected"],
                "sysmon_available": self._sysmon_available,
                "last_poll": self._last_poll.isoformat() if self._last_poll else None,
                "mode": self._evt_mode,
                "evt_subscriptions": len(self._evt_subscriptions),
            },
        }

    async def _poll_loop(self) -> None:
        """Periodically collect events from Windows Event Logs."""
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._collect_events()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("event_log_poll_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _collect_events(self) -> None:
        """Collect events from all monitored channels."""
        loop = asyncio.get_event_loop()

        # Collect Security events
        security_ids = list(SECURITY_EVENT_IDS.keys())
        security_raw = await loop.run_in_executor(
            None, self._query_event_log, "Security", security_ids
        )
        for raw in security_raw:
            event = self._parse_event(raw, "Security", SECURITY_EVENT_IDS)
            if event:
                self._events.append(event)
                self._update_stats(event)

        # Collect System events
        system_ids = list(SYSTEM_EVENT_IDS.keys())
        system_raw = await loop.run_in_executor(
            None, self._query_event_log, "System", system_ids
        )
        for raw in system_raw:
            event = self._parse_event(raw, "System", SYSTEM_EVENT_IDS)
            if event:
                self._events.append(event)
                self._update_stats(event)

        # Collect Sysmon events if available
        if self._enable_sysmon and self._sysmon_available:
            sysmon_ids = list(SYSMON_EVENT_IDS.keys())
            sysmon_raw = await loop.run_in_executor(
                None, self._query_event_log,
                "Microsoft-Windows-Sysmon/Operational", sysmon_ids,
            )
            for raw in sysmon_raw:
                event = self._parse_event(raw, "Sysmon", SYSMON_EVENT_IDS)
                if event:
                    self._events.append(event)
                    self._update_stats(event)

        self._last_poll = datetime.now(timezone.utc)
        self.heartbeat()

    def _query_event_log(self, log_name: str, event_ids: list[int]) -> list[dict]:
        """Query Windows Event Log via PowerShell. Returns list of raw event dicts."""
        ids_str = ",".join(str(eid) for eid in event_ids)
        ps_command = (
            f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}';"
            f"Id={ids_str}}} -MaxEvents {self._max_events_per_query} "
            f"| Select-Object TimeCreated,Id,LevelDisplayName,Message "
            f"| ConvertTo-Json"
        )

        try:
            result = self._run_cmd(
                ["powershell", "-NoProfile", "-Command", ps_command]
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []

            parsed = json.loads(result.stdout)

            # PowerShell returns a single object (not array) when there is only one result
            if isinstance(parsed, dict):
                parsed = [parsed]

            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            self.logger.debug("event_log_json_parse_error", log_name=log_name)
            return []
        except Exception as e:
            self.logger.debug("event_log_query_error", log_name=log_name, error=str(e))
            return []

    def _run_cmd(self, args: list[str]) -> subprocess.CompletedProcess:
        """Execute a subprocess command with argument list (never shell=True)."""
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def _check_sysmon_available(self) -> bool:
        """Check if Sysmon is installed by querying its event log."""
        try:
            result = self._run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' "
                "-ErrorAction Stop | Select-Object -ExpandProperty LogName",
            ])
            return result.returncode == 0 and "Sysmon" in result.stdout
        except Exception:
            return False

    def _parse_event(
        self,
        raw: dict,
        channel: str,
        event_id_map: dict[int, tuple[str, str, str]],
    ) -> dict | None:
        """Parse a raw PowerShell event dict into a normalized event record."""
        try:
            event_id = raw.get("Id")
            if event_id is None:
                return None

            event_id = int(event_id)
            message = raw.get("Message") or ""
            summary = message.split("\n")[0].strip() if message else ""
            details = self._parse_message_details(message)

            # Determine base severity from mapping
            mapping = event_id_map.get(event_id)
            if mapping:
                _, description, base_severity = mapping
            else:
                description = f"Event {event_id}"
                base_severity = "low"

            # Elevate severity based on context
            severity = self._classify_severity(event_id, base_severity, message, details)

            # Parse timestamp — PowerShell ConvertTo-Json serializes DateTime as
            # /Date(milliseconds)/ or ISO string depending on PS version
            timestamp = self._parse_ps_timestamp(raw.get("TimeCreated"))

            return {
                "timestamp": timestamp,
                "event_id": event_id,
                "channel": channel,
                "severity": severity,
                "description": description,
                "summary": summary,
                "raw_message": message[:2000],  # Truncate very long messages
                "details": details,
                "level": raw.get("LevelDisplayName") or "",
            }
        except Exception as e:
            self.logger.debug("event_parse_error", error=str(e))
            return None

    def _parse_ps_timestamp(self, ts_value) -> str:
        """Parse PowerShell timestamp into ISO format string."""
        if ts_value is None:
            return datetime.now(timezone.utc).isoformat()

        if isinstance(ts_value, str):
            # Handle /Date(1234567890123)/ format
            if ts_value.startswith("/Date(") and ts_value.endswith(")/"):
                try:
                    ms = int(ts_value[6:-2])
                    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            # Try direct ISO parse
            try:
                return datetime.fromisoformat(ts_value).isoformat()
            except (ValueError, TypeError):
                pass

        return datetime.now(timezone.utc).isoformat()

    def _parse_message_details(self, message: str) -> dict:
        """Parse key-value pairs from Windows Event Log message body."""
        details = {}
        if not message:
            return details

        for line in message.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key and value and len(key) < 80:
                    details[key] = value

        return details

    def _classify_severity(
        self,
        event_id: int,
        base_severity: str,
        message: str,
        details: dict,
    ) -> str:
        """Classify event severity, elevating based on contextual indicators."""
        severity = base_severity
        message_lower = message.lower()

        # 4672 — Special privileges assigned: critical only for non-routine accounts.
        # SYSTEM (S-1-5-18), LOCAL SERVICE (S-1-5-19), NETWORK SERVICE (S-1-5-20)
        # receive these privileges on every logon — that's normal Windows behaviour.
        if event_id == 4672:
            sid = details.get("Security ID", "")
            account = details.get("Account Name", "").upper()
            routine_sids = ("S-1-5-18", "S-1-5-19", "S-1-5-20")
            routine_accounts = ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
            if sid in routine_sids or account in routine_accounts:
                return "low"
            return "critical"

        # 7045 — New service installed: elevate to critical if suspicious
        if event_id == 7045:
            service_name = details.get("Service Name", "").lower()
            image_path = details.get("Service File Name", "").lower()
            combined = service_name + " " + image_path
            for keyword in SUSPICIOUS_SERVICE_KEYWORDS:
                if keyword in combined:
                    return "critical"
            return "high"

        # 4688 — Process creation: elevate if parent is suspicious
        if event_id == 4688:
            parent_name = details.get("Creator Process Name", "").lower()
            new_process = details.get("New Process Name", "").lower()
            for suspicious in SUSPICIOUS_PARENTS:
                if suspicious in parent_name or suspicious in new_process:
                    return "high"
            return "low"

        # 4720 — Account created: always high
        if event_id == 4720:
            return "high"

        # 4732 — User added to privileged group: elevate to critical
        if event_id == 4732:
            group_name = details.get("Group Name", "").lower()
            if "admin" in group_name or "domain" in group_name:
                return "critical"
            return "high"

        # 4625 — Failed logon
        if event_id == 4625:
            return "medium"

        # 4624 — Successful logon
        if event_id == 4624:
            logon_type = details.get("Logon Type", "")
            # Type 10 = RemoteInteractive (RDP), Type 3 = Network
            if logon_type in ("10", "3"):
                return "medium"
            return "low"

        return severity

    def _update_stats(self, event: dict) -> None:
        """Update running statistics counters."""
        self._stats["total_collected"] += 1

        eid = str(event["event_id"])
        self._stats["by_event_id"][eid] = self._stats["by_event_id"].get(eid, 0) + 1

        severity = event["severity"]
        if severity in self._stats["by_severity"]:
            self._stats["by_severity"][severity] += 1

        channel = event["channel"]
        if channel in self._stats["by_channel"]:
            self._stats["by_channel"][channel] += 1

        # Phase 15: Publish to EventBus
        if self._event_bus:
            event_type = "sysmon_event" if channel == "Sysmon" else "security_event"
            self._event_bus.publish(event_type, event)

    async def _start_evt_subscribe(self) -> bool:
        """Try to start EvtSubscribe-based real-time event collection."""
        try:
            from ..utils.win32_evtlog import EvtSubscription, is_available as evt_is_available
            if not evt_is_available():
                return False

            loop = asyncio.get_event_loop()

            # Security channel subscription
            sec_ids = list(SECURITY_EVENT_IDS.keys())
            sec_query = " or ".join(f"EventID={eid}" for eid in sec_ids)
            sec_xpath = f"*[System[{sec_query}]]"

            def _sec_callback(event_xml: str):
                try:
                    sub = self._evt_subscriptions[0] if self._evt_subscriptions else None
                    if sub:
                        parsed = sub.parse_event_xml(event_xml)
                        event = self._parse_event(parsed, "Security", SECURITY_EVENT_IDS)
                        if event:
                            self._events.append(event)
                            self._update_stats(event)
                except Exception:
                    pass

            sec_sub = EvtSubscription("Security", sec_xpath, _sec_callback)
            started = await loop.run_in_executor(None, sec_sub.start)
            if started:
                self._evt_subscriptions.append(sec_sub)
                self.logger.info("evt_subscribe_security_active")

            # Sysmon channel subscription
            if self._enable_sysmon and self._sysmon_available:
                sysmon_ids = list(SYSMON_EVENT_IDS.keys())
                sysmon_query = " or ".join(f"EventID={eid}" for eid in sysmon_ids)
                sysmon_xpath = f"*[System[{sysmon_query}]]"

                def _sysmon_callback(event_xml: str):
                    try:
                        sub = self._evt_subscriptions[-1] if self._evt_subscriptions else None
                        if sub:
                            parsed = sub.parse_event_xml(event_xml)
                            event = self._parse_event(parsed, "Sysmon", SYSMON_EVENT_IDS)
                            if event:
                                self._events.append(event)
                                self._update_stats(event)
                    except Exception:
                        pass

                sysmon_sub = EvtSubscription(
                    "Microsoft-Windows-Sysmon/Operational", sysmon_xpath, _sysmon_callback
                )
                started = await loop.run_in_executor(None, sysmon_sub.start)
                if started:
                    self._evt_subscriptions.append(sysmon_sub)
                    self.logger.info("evt_subscribe_sysmon_active")

            return len(self._evt_subscriptions) > 0
        except Exception as e:
            self.logger.debug("evt_subscribe_init_failed", error=str(e))
            return False

    # --- Public API ---

    def get_events(self, limit: int = 100) -> list[dict]:
        """Return the most recent events, newest first."""
        events = list(self._events)
        events.reverse()
        return events[:limit]

    def get_events_by_type(self, event_type: int, limit: int = 100) -> list[dict]:
        """Return events filtered by event ID, newest first."""
        filtered = [e for e in self._events if e["event_id"] == event_type]
        filtered.reverse()
        return filtered[:limit]

    def get_events_by_severity(self, severity: str, limit: int = 100) -> list[dict]:
        """Return events filtered by severity level, newest first."""
        filtered = [e for e in self._events if e["severity"] == severity]
        filtered.reverse()
        return filtered[:limit]

    def get_stats(self) -> dict:
        """Return event collection statistics."""
        return {
            **self._stats,
            "buffered_events": len(self._events),
            "max_events": self._max_events,
            "sysmon_available": self._sysmon_available,
            "last_poll": self._last_poll.isoformat() if self._last_poll else None,
        }

    def get_recent_critical(self, limit: int = 20) -> list[dict]:
        """Return recent critical and high severity events."""
        critical_events = [
            e for e in self._events
            if e["severity"] in ("critical", "high")
        ]
        critical_events.reverse()
        return critical_events[:limit]
