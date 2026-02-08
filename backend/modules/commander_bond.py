"""Commander Bond Module -- autonomous threat intelligence operative.

Scans open-source threat feeds on a schedule to identify new vulnerabilities,
malware samples, C2 infrastructure, and IOCs. Reports are delivered in Bond's
voice: precise, understated, lethally calm.

Data sources (all free, no API keys required):
  - CISA Known Exploited Vulnerabilities (KEV)
  - NVD CVE 2.0 API (recent high-severity CVEs)
  - URLhaus (recent malware URLs)
  - Feodo Tracker (botnet C2 IPs)
  - ThreatFox (recent IOCs)
  - MalwareBazaar (recent malware samples)
"""

import asyncio
import hashlib
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp

from .base_module import BaseModule
from ..utils.logging import get_logger

# ---------------------------------------------------------------------------
# Feed endpoints
# ---------------------------------------------------------------------------
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"

# ---------------------------------------------------------------------------
# Severity labels -- Bond style
# ---------------------------------------------------------------------------
SEVERITY_LABELS = {
    "critical": "License to kill -- immediate action required",
    "high": "Marked for elimination",
    "medium": "Under surveillance",
    "low": "Noted in the dossier",
}

logger = get_logger("module.commander_bond")


class CommanderBond(BaseModule):
    """Autonomous threat intelligence operative that scans open-source feeds.

    Periodically fetches data from six free threat intelligence sources,
    deduplicates findings, and produces Bond-style intelligence briefings
    complete with Cereberus-specific remediation prompts.
    """

    def __init__(self, config: dict | None = None):
        super().__init__(name="commander_bond", config=config)

        cfg = config or {}
        self._scan_interval: int = cfg.get("scan_interval", 21600)  # 6 hours
        self._reports: deque[dict] = deque(maxlen=30)
        self._last_scan: Optional[datetime] = None
        self._known_cve_ids: set[str] = set()
        self._known_ioc_hashes: set[str] = set()
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._scan_task: Optional[asyncio.Task] = None
        self._alert_manager = None

        # Running counters
        self._total_scans: int = 0
        self._total_threats_found: int = 0
        self._report_sequence: int = 0
        self._scanning: bool = False

        # Neutralized threat IDs — filtered out of all responses
        self._neutralized_ids: set[str] = set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the intelligence gathering loop."""
        self.running = True
        self.health_status = "running"
        self.logger.info("commander_bond_starting", status="Bond is in the field...")

        self._http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "Cereberus-CommanderBond/1.0"},
        )

        # Execute an initial scan immediately
        await self._execute_scan()

        # Start the recurring scan loop
        self._scan_task = asyncio.create_task(self._scan_loop())
        self.heartbeat()
        self.logger.info("commander_bond_started", status="Intelligence gathered")

    async def stop(self) -> None:
        """Recall the operative from the field."""
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None
        self.health_status = "stopped"
        self.logger.info("commander_bond_stopped", status="Bond has returned to MI6")

    async def health_check(self) -> dict:
        """Return module health status."""
        self.heartbeat()
        latest = self.get_latest_report()
        return {
            "status": self.health_status,
            "details": {
                "total_scans": self._total_scans,
                "total_threats_found": self._total_threats_found,
                "reports_buffered": len(self._reports),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                "latest_threat_count": latest["threat_count"] if latest else 0,
            },
        }

    # ------------------------------------------------------------------
    # External integrations
    # ------------------------------------------------------------------

    def set_alert_manager(self, manager) -> None:
        """Attach an AlertManager for auto-creating CRITICAL alerts."""
        self._alert_manager = manager
        self.logger.info("commander_bond_alert_manager_attached")

    def get_status(self) -> dict:
        """Return Bond's operational status for the frontend."""
        latest = self.get_latest_report()  # already filtered
        # Compute next scan time
        next_scan = None
        if self._last_scan and self.running:
            next_scan = (self._last_scan + timedelta(seconds=self._scan_interval)).isoformat()

        state = "offline"
        if self.running:
            state = "scanning" if self._scanning else "idle"

        return {
            "state": state,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            "next_scan": next_scan,
            "threat_count": latest["threat_count"] if latest else 0,
            "scan_interval_seconds": self._scan_interval,
            "total_scans": self._total_scans,
            "total_threats_found": self._total_threats_found,
            "reports_buffered": len(self._reports),
            "neutralized_count": len(self._neutralized_ids),
        }

    # ------------------------------------------------------------------
    # Scan loop
    # ------------------------------------------------------------------

    async def _scan_loop(self) -> None:
        """Run scans every ``_scan_interval`` seconds."""
        while self.running:
            try:
                await asyncio.sleep(self._scan_interval)
                if self.running:
                    await self._execute_scan()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error("commander_bond_scan_loop_error", error=str(exc))
                await asyncio.sleep(self._scan_interval)

    async def _execute_scan(self) -> None:
        """Orchestrate a full intelligence sweep across all sources."""
        self._scanning = True
        scan_start = time.monotonic()
        self.logger.info("commander_bond_scan_begin", status="Bond is in the field...")

        findings: list[dict] = []

        # Run all source checks concurrently
        results = await asyncio.gather(
            self._check_cisa_kev(),
            self._check_nvd_cves(),
            self._check_urlhaus(),
            self._check_feodo_c2(),
            self._check_threatfox(),
            self._check_malware_bazaar(),
            return_exceptions=True,
        )

        source_names = [
            "CISA KEV", "NVD CVE", "URLhaus",
            "Feodo Tracker", "ThreatFox", "MalwareBazaar",
        ]
        for name, result in zip(source_names, results):
            if isinstance(result, Exception):
                self.logger.error(
                    "commander_bond_source_error", source=name, error=str(result),
                )
            elif isinstance(result, list):
                findings.extend(result)

        scan_duration = round(time.monotonic() - scan_start, 2)
        report = self._generate_report(findings, scan_duration)

        self._reports.append(report)
        self._total_scans += 1
        self._total_threats_found += report["threat_count"]
        self._last_scan = datetime.now(timezone.utc)
        self.heartbeat()

        # Create alerts for critical threats
        if self._alert_manager:
            for threat in report["threats"]:
                if threat["severity"] == "critical":
                    try:
                        await self._alert_manager.create_alert(
                            severity="critical",
                            module_source="commander_bond",
                            title=f"BOND INTELLIGENCE: {threat['name']}",
                            description=threat["bond_assessment"][:500],
                            details=threat,
                        )
                    except Exception as exc:
                        self.logger.error(
                            "commander_bond_alert_error", error=str(exc),
                        )

        self._scanning = False
        level = "all_clear" if report["all_clear"] else f"{report['threat_count']} threats"
        self.logger.info(
            "commander_bond_scan_complete",
            status="Shaken, not stirred -- analysis complete",
            threats=report["threat_count"],
            duration=scan_duration,
            level=level,
        )

    # ------------------------------------------------------------------
    # Source: CISA KEV
    # ------------------------------------------------------------------

    async def _check_cisa_kev(self) -> list[dict]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("GET", CISA_KEV_URL)
            if not data:
                return findings

            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities[-30:]:  # Check the 30 most recent
                cve_id = vuln.get("cveID", "")
                if not cve_id or cve_id in self._known_cve_ids:
                    continue

                self._known_cve_ids.add(cve_id)
                findings.append({
                    "id": cve_id,
                    "name": f"{cve_id}: {vuln.get('vulnerabilityName', 'Unknown')}",
                    "category": "known_exploited_vulnerability",
                    "severity": "critical",
                    "source": "CISA KEV",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "kev",
                        "cve": cve_id,
                        "name": vuln.get("vulnerabilityName", ""),
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                    }),
                    "iocs": [cve_id],
                    "mitre_techniques": ["T1190"],  # Exploit Public-Facing Application
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "cve",
                        "cve": cve_id,
                        "name": vuln.get("vulnerabilityName", ""),
                        "vendor": vuln.get("vendorProject", ""),
                    }),
                    "raw": {
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "required_action": vuln.get("requiredAction", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_cisa_kev_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: NVD CVEs
    # ------------------------------------------------------------------

    async def _check_nvd_cves(self) -> list[dict]:
        """Fetch recent CVEs from NVD, filtered to CVSS >= 7.0 and Windows-relevant."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("GET", NVD_CVE_URL)
            if not data:
                return findings

            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id or cve_id in self._known_cve_ids:
                    continue

                # Extract CVSS score
                cvss_score = self._extract_cvss_score(cve_data)
                if cvss_score < 7.0:
                    continue

                # Check Windows relevance from descriptions or configurations
                description = self._extract_cve_description(cve_data)
                if not self._is_windows_relevant(description, cve_data):
                    continue

                self._known_cve_ids.add(cve_id)
                severity = "critical" if cvss_score >= 9.0 else "high"

                findings.append({
                    "id": cve_id,
                    "name": f"{cve_id} (CVSS {cvss_score})",
                    "category": "cve",
                    "severity": severity,
                    "source": "NVD",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "cve",
                        "cve": cve_id,
                        "cvss": cvss_score,
                        "description": description[:200],
                    }),
                    "iocs": [cve_id],
                    "mitre_techniques": ["T1203"],  # Exploitation for Client Execution
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "cve",
                        "cve": cve_id,
                        "name": description[:120],
                        "vendor": "multiple",
                    }),
                    "raw": {
                        "cvss_score": cvss_score,
                        "description": description[:500],
                        "published": cve_data.get("published", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_nvd_error", error=str(exc))
        return findings

    @staticmethod
    def _extract_cvss_score(cve_data: dict) -> float:
        """Extract the highest CVSS score from a CVE record."""
        metrics = cve_data.get("metrics", {})
        best = 0.0
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            for m in metric_list:
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                if score > best:
                    best = score
        return best

    @staticmethod
    def _extract_cve_description(cve_data: dict) -> str:
        """Extract English description from a CVE record."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    @staticmethod
    def _is_windows_relevant(description: str, cve_data: dict) -> bool:
        """Heuristic check for Windows relevance."""
        windows_keywords = {
            "windows", "microsoft", "win32", "active directory", "ntlm",
            "smb", "rdp", "exchange", "iis", ".net", "powershell",
            "office", "outlook", "defender", "kernel32", "ntdll",
        }
        text = description.lower()
        for keyword in windows_keywords:
            if keyword in text:
                return True

        # Also check configurations / affected products
        configs = cve_data.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "").lower()
                    if "microsoft" in criteria or "windows" in criteria:
                        return True
        return False

    # ------------------------------------------------------------------
    # Source: URLhaus
    # ------------------------------------------------------------------

    async def _check_urlhaus(self) -> list[dict]:
        """Fetch recent malware distribution URLs from URLhaus."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("POST", URLHAUS_RECENT_URL)
            if not data:
                return findings

            urls = data.get("urls", [])
            for entry in urls[:20]:
                url = entry.get("url", "")
                url_hash = hashlib.sha256(url.encode()).hexdigest()
                if url_hash in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(url_hash)
                threat_type = entry.get("threat", "malware_download")
                tags = entry.get("tags") or []

                findings.append({
                    "id": f"URLHAUS-{entry.get('id', url_hash[:8])}",
                    "name": f"Malware URL: {url[:80]}",
                    "category": "malware_url",
                    "severity": "high",
                    "source": "URLhaus",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "malware_url",
                        "url": url,
                        "threat": threat_type,
                        "tags": tags,
                    }),
                    "iocs": [url],
                    "mitre_techniques": ["T1566.002"],  # Phishing: Spear-phishing Link
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "malware",
                        "url": url,
                        "threat": threat_type,
                    }),
                    "raw": {
                        "url": url,
                        "url_status": entry.get("url_status", ""),
                        "threat": threat_type,
                        "tags": tags,
                        "date_added": entry.get("dateadded", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_urlhaus_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: Feodo Tracker
    # ------------------------------------------------------------------

    async def _check_feodo_c2(self) -> list[dict]:
        """Fetch recommended C2 IP blocklist from Feodo Tracker."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("GET", FEODO_BLOCKLIST_URL)
            if not data:
                return findings

            entries = data if isinstance(data, list) else data.get("data", data.get("entries", []))
            if not isinstance(entries, list):
                return findings

            for entry in entries[:20]:
                if isinstance(entry, dict):
                    ip = entry.get("ip_address", entry.get("dst_ip", ""))
                    port = entry.get("dst_port", entry.get("port", ""))
                    malware = entry.get("malware", "unknown")
                    status = entry.get("status", "")
                else:
                    ip = str(entry)
                    port = ""
                    malware = "unknown"
                    status = ""

                if not ip:
                    continue

                ip_hash = hashlib.sha256(ip.encode()).hexdigest()
                if ip_hash in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(ip_hash)
                findings.append({
                    "id": f"FEODO-{ip_hash[:12]}",
                    "name": f"Botnet C2: {ip}:{port} ({malware})",
                    "category": "c2_infrastructure",
                    "severity": "critical",
                    "source": "Feodo Tracker",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "c2",
                        "ip": ip,
                        "port": port,
                        "malware": malware,
                    }),
                    "iocs": [ip],
                    "mitre_techniques": ["T1071.001"],  # Application Layer Protocol
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "c2",
                        "ip": ip,
                        "port": port,
                        "malware": malware,
                    }),
                    "raw": {
                        "ip": ip,
                        "port": port,
                        "malware": malware,
                        "status": status,
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_feodo_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: ThreatFox
    # ------------------------------------------------------------------

    async def _check_threatfox(self) -> list[dict]:
        """Fetch recent IOCs from ThreatFox."""
        findings: list[dict] = []
        try:
            payload = {"query": "get_iocs", "days": 1}
            data = await self._fetch_json("POST", THREATFOX_API_URL, json_body=payload)
            if not data or data.get("query_status") != "ok":
                return findings

            iocs = data.get("data", [])
            if not isinstance(iocs, list):
                return findings

            for entry in iocs[:20]:
                ioc_value = entry.get("ioc", "")
                ioc_hash = hashlib.sha256(ioc_value.encode()).hexdigest()
                if ioc_hash in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(ioc_hash)
                malware = entry.get("malware_printable", "unknown")
                ioc_type = entry.get("ioc_type", "unknown")
                threat_type = entry.get("threat_type", "unknown")
                confidence = entry.get("confidence_level", 0)

                severity = "critical" if confidence >= 75 else "high" if confidence >= 50 else "medium"

                findings.append({
                    "id": f"TFOX-{entry.get('id', ioc_hash[:8])}",
                    "name": f"ThreatFox IOC: {malware} ({ioc_type})",
                    "category": "ioc",
                    "severity": severity,
                    "source": "ThreatFox",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "ioc",
                        "ioc_value": ioc_value,
                        "malware": malware,
                        "ioc_type": ioc_type,
                        "confidence": confidence,
                    }),
                    "iocs": [ioc_value],
                    "mitre_techniques": entry.get("mitre_attack", ["T1059"]),
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "malware",
                        "malware": malware,
                        "ioc_type": ioc_type,
                        "threat": threat_type,
                    }),
                    "raw": {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "threat_type": threat_type,
                        "malware": malware,
                        "confidence": confidence,
                        "tags": entry.get("tags"),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_threatfox_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: MalwareBazaar
    # ------------------------------------------------------------------

    async def _check_malware_bazaar(self) -> list[dict]:
        """Fetch recent malware samples from MalwareBazaar."""
        findings: list[dict] = []
        try:
            payload = {"query": "get_recent", "selector": "time"}
            data = await self._fetch_json("POST", MALWAREBAZAAR_API_URL, json_body=payload)
            if not data or data.get("query_status") != "ok":
                return findings

            samples = data.get("data", [])
            if not isinstance(samples, list):
                return findings

            for sample in samples[:15]:
                sha256 = sample.get("sha256_hash", "")
                if not sha256 or sha256 in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(sha256)
                file_name = sample.get("file_name", "unknown")
                file_type = sample.get("file_type", "unknown")
                signature = sample.get("signature") or "unsigned"
                tags = sample.get("tags") or []

                # Determine severity from tags / signature
                severity = "high"
                ransomware_indicators = {"ransomware", "ransom", "locker", "crypt"}
                if any(t.lower() in ransomware_indicators for t in tags):
                    severity = "critical"
                if signature and any(k in signature.lower() for k in ransomware_indicators):
                    severity = "critical"

                findings.append({
                    "id": f"MBAZ-{sha256[:12]}",
                    "name": f"Malware sample: {file_name} ({file_type})",
                    "category": "malware_sample",
                    "severity": severity,
                    "source": "MalwareBazaar",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "malware_sample",
                        "file_name": file_name,
                        "file_type": file_type,
                        "signature": signature,
                        "sha256": sha256,
                    }),
                    "iocs": [sha256],
                    "mitre_techniques": ["T1204.002"],  # User Execution: Malicious File
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "ransomware" if severity == "critical" else "malware",
                        "file_name": file_name,
                        "sha256": sha256,
                        "signature": signature,
                    }),
                    "raw": {
                        "sha256": sha256,
                        "md5": sample.get("md5_hash", ""),
                        "file_name": file_name,
                        "file_type": file_type,
                        "file_size": sample.get("file_size", 0),
                        "signature": signature,
                        "tags": tags,
                        "first_seen": sample.get("first_seen", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_malwarebazaar_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _fetch_json(
        self,
        method: str,
        url: str,
        json_body: dict | None = None,
    ) -> dict | list | None:
        """Fetch JSON from a URL with timeout and error handling."""
        if not self._http_session or self._http_session.closed:
            self.logger.warning("commander_bond_no_session")
            return None

        try:
            if method.upper() == "POST":
                async with self._http_session.post(url, json=json_body) as resp:
                    if resp.status != 200:
                        self.logger.warning(
                            "commander_bond_http_error",
                            url=url, status=resp.status,
                        )
                        return None
                    return await resp.json(content_type=None)
            else:
                async with self._http_session.get(url) as resp:
                    if resp.status != 200:
                        self.logger.warning(
                            "commander_bond_http_error",
                            url=url, status=resp.status,
                        )
                        return None
                    return await resp.json(content_type=None)
        except asyncio.TimeoutError:
            self.logger.warning("commander_bond_timeout", url=url)
            return None
        except Exception as exc:
            self.logger.warning("commander_bond_fetch_error", url=url, error=str(exc))
            return None

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _generate_report(self, findings: list[dict], scan_duration: float) -> dict:
        """Compile findings into a Bond intelligence briefing."""
        now = datetime.now(timezone.utc)
        self._report_sequence += 1
        report_id = f"BOND-{now.strftime('%Y-%m-%d')}-{self._report_sequence:03d}"

        all_clear = len(findings) == 0

        if all_clear:
            summary = "The name is Bond. All clear on the perimeter."
        elif len(findings) == 1:
            summary = (
                f"Bond identified 1 threat during the sweep. "
                f"Recommend immediate review of the dossier."
            )
        else:
            critical_count = sum(1 for f in findings if f.get("severity") == "critical")
            if critical_count > 0:
                summary = (
                    f"Bond identified {len(findings)} threats, {critical_count} critical. "
                    f"License to kill has been granted -- act immediately."
                )
            else:
                summary = (
                    f"Bond identified {len(findings)} threats during the sweep. "
                    f"All targets are under surveillance."
                )

        return {
            "id": report_id,
            "timestamp": now.isoformat(),
            "scan_duration_seconds": scan_duration,
            "status": "INTELLIGENCE GATHERED" if not all_clear else "ALL CLEAR",
            "threat_count": len(findings),
            "threats": findings,
            "summary": summary,
            "all_clear": all_clear,
        }

    # ------------------------------------------------------------------
    # Bond personality
    # ------------------------------------------------------------------

    @staticmethod
    def _bond_assessment_text(threat: dict) -> str:
        """Generate a Bond-style assessment for a threat."""
        threat_type = threat.get("type", "unknown")

        if threat_type == "kev":
            return (
                f"THREAT DOSSIER: {threat.get('cve', 'Unknown CVE')} -- "
                f"{threat.get('name', 'classified vulnerability')}. "
                f"Vendor: {threat.get('vendor', 'unknown')}, "
                f"Product: {threat.get('product', 'unknown')}. "
                f"This exploit is confirmed active in the wild. "
                f"Required action: {threat.get('action', 'patch immediately')}. "
                f"Deadline: {threat.get('due_date', 'yesterday')}. "
                f"License to kill -- immediate action required."
            )

        if threat_type == "cve":
            cvss = threat.get("cvss", "N/A")
            return (
                f"THREAT DOSSIER: {threat.get('cve', 'Unknown CVE')} "
                f"with CVSS {cvss}. "
                f"{threat.get('description', 'Details classified.')} "
                f"{'License to kill -- immediate action required.' if isinstance(cvss, (int, float)) and cvss >= 9.0 else 'Marked for elimination.'}"
            )

        if threat_type == "malware_url":
            return (
                f"THREAT DOSSIER: Malware distribution point identified at "
                f"{threat.get('url', 'classified location')}. "
                f"Threat classification: {threat.get('threat', 'unknown')}. "
                f"Tags: {', '.join(threat.get('tags', [])[:5]) or 'none'}. "
                f"Marked for elimination."
            )

        if threat_type == "c2":
            return (
                f"THREAT DOSSIER: Command & control server detected. "
                f"Target: {threat.get('ip', 'unknown')}:{threat.get('port', '?')}. "
                f"Associated malware family: {threat.get('malware', 'unknown')}. "
                f"This is an active enemy communication channel. "
                f"License to kill -- immediate action required."
            )

        if threat_type == "ioc":
            return (
                f"THREAT DOSSIER: Indicator of compromise intercepted. "
                f"Type: {threat.get('ioc_type', 'unknown')}. "
                f"Malware: {threat.get('malware', 'unknown')}. "
                f"Confidence: {threat.get('confidence', 0)}%. "
                f"{'License to kill -- immediate action required.' if threat.get('confidence', 0) >= 75 else 'Under surveillance.'}"
            )

        if threat_type == "malware_sample":
            return (
                f"THREAT DOSSIER: Malware sample acquired. "
                f"Filename: {threat.get('file_name', 'unknown')}. "
                f"Type: {threat.get('file_type', 'unknown')}. "
                f"Signature: {threat.get('signature', 'unsigned')}. "
                f"SHA256: {threat.get('sha256', 'unknown')[:16]}... "
                f"Marked for elimination."
            )

        return (
            f"THREAT DOSSIER: Unclassified threat detected. "
            f"Details: {str(threat)[:200]}. Under surveillance."
        )

    # ------------------------------------------------------------------
    # Cereberus remediation prompts
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_cereberus_prompt(threat: dict) -> str:
        """Generate a Cereberus-specific remediation prompt for a threat."""
        threat_type = threat.get("type", "unknown")

        if threat_type == "cve":
            return (
                f"Vulnerability {threat.get('cve', 'unknown')} "
                f"({threat.get('name', 'unnamed')}) reported by "
                f"{threat.get('vendor', 'unknown')}. "
                f"Recommended Cereberus actions: "
                f"1) Update vuln_scanner signatures to detect this CVE. "
                f"2) Add {threat.get('cve', '')} to IOC database. "
                f"3) Scan all monitored hosts for affected software versions."
            )

        if threat_type == "malware":
            return (
                f"Malware activity detected -- {threat.get('malware', threat.get('threat', 'unknown'))}. "
                f"Recommended Cereberus actions: "
                f"1) Add IOC indicators to rule_engine detection rules. "
                f"2) Update IOC feed with new malware hashes/URLs. "
                f"3) Scan file_integrity monitored paths for matching artifacts. "
                f"4) Alert process_analyzer to flag processes loading related modules."
            )

        if threat_type == "c2":
            return (
                f"C2 server identified: {threat.get('ip', 'unknown')}:{threat.get('port', '?')} "
                f"(malware family: {threat.get('malware', 'unknown')}). "
                f"Recommended Cereberus actions: "
                f"1) Add IP to firewall block list via remediation engine (block_ip action). "
                f"2) Update IOC database with C2 IP and associated indicators. "
                f"3) Scan network_sentinel connection logs for any past contact. "
                f"4) Check brute_force_shield logs for related activity."
            )

        if threat_type == "ransomware":
            return (
                f"Ransomware sample detected -- {threat.get('signature', threat.get('file_name', 'unknown'))}. "
                f"SHA256: {threat.get('sha256', 'unknown')}. "
                f"Recommended Cereberus actions: "
                f"1) Update ransomware_detector pattern database with sample hash. "
                f"2) Add file hash to IOC feed for real-time matching. "
                f"3) Verify file_integrity baselines for critical system directories. "
                f"4) Prepare incident response playbook for ransomware containment."
            )

        return (
            f"Threat detected: {str(threat)[:200]}. "
            f"Recommended Cereberus actions: "
            f"1) Review and update detection rules. "
            f"2) Add relevant IOCs to the database."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _filter_report(self, report: dict) -> dict:
        """Return a copy of the report with neutralized threats removed."""
        if not self._neutralized_ids:
            return report
        active_threats = [
            t for t in report.get("threats", [])
            if t.get("id") not in self._neutralized_ids
        ]
        return {
            **report,
            "threats": active_threats,
            "threat_count": len(active_threats),
            "all_clear": len(active_threats) == 0,
        }

    def get_reports(self) -> list[dict]:
        """Return all buffered intelligence reports, newest first."""
        reports = [self._filter_report(r) for r in self._reports]
        reports.reverse()
        return reports

    def get_latest_report(self) -> Optional[dict]:
        """Return the most recent intelligence report, or None."""
        if not self._reports:
            return None
        return self._filter_report(self._reports[-1])

    def get_all_threats(
        self,
        category: str | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """Return all threats across all reports, optionally filtered.

        Args:
            category: Filter by threat category (e.g. 'c2_infrastructure', 'cve').
            severity: Filter by severity level ('critical', 'high', 'medium', 'low').

        Returns:
            List of threat dicts, newest first.
        """
        threats: list[dict] = []
        for report in reversed(self._reports):
            for threat in report.get("threats", []):
                if threat.get("id") in self._neutralized_ids:
                    continue
                if category and threat.get("category") != category:
                    continue
                if severity and threat.get("severity") != severity:
                    continue
                threats.append(threat)
        return threats

    def neutralize_threat(self, threat_id: str) -> bool:
        """Mark a threat as neutralized — removes it from all responses.

        Returns True if the threat was found and neutralized, False if not found.
        """
        # Verify the threat exists in at least one report
        for report in self._reports:
            for threat in report.get("threats", []):
                if threat.get("id") == threat_id:
                    self._neutralized_ids.add(threat_id)
                    self.logger.info(
                        "commander_bond_threat_neutralized",
                        threat_id=threat_id,
                        status="Target eliminated.",
                    )
                    return True
        return False

    def neutralize_all(self) -> int:
        """Mark all current threats as neutralized. Returns count neutralized."""
        count = 0
        for report in self._reports:
            for threat in report.get("threats", []):
                tid = threat.get("id")
                if tid and tid not in self._neutralized_ids:
                    self._neutralized_ids.add(tid)
                    count += 1
        if count:
            self.logger.info(
                "commander_bond_all_neutralized",
                count=count,
                status="All targets eliminated.",
            )
        return count
