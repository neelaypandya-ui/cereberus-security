"""VPN Guardian Module — orchestrates all VPN protection sub-modules.

Coordinates VPN detection, kill switch, leak checking, route monitoring,
and config auditing into a unified security module.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

from ..modules.base_module import BaseModule
from ..vpn.config_auditor import ConfigAuditor
from ..vpn.detector import VPNDetector, VPNState
from ..vpn.kill_switch import KillSwitch
from ..vpn.leak_checker import LeakChecker
from ..vpn.route_monitor import RouteMonitor
from ..utils.logging import get_logger

logger = get_logger("module.vpn_guardian")


class VPNGuardian(BaseModule):
    """Orchestrator module for all VPN security features.

    Manages:
    - VPN connection detection and monitoring
    - Kill switch activation/deactivation
    - DNS/IP/IPv6 leak detection
    - Route table monitoring
    - Config file auditing
    """

    def __init__(self, config: dict | None = None):
        super().__init__(name="vpn_guardian", config=config)

        cfg = config or {}

        self.detector = VPNDetector(
            trusted_interfaces=cfg.get("vpn_trusted_interfaces", [])
        )
        self.kill_switch = KillSwitch(
            mode=cfg.get("vpn_kill_switch_mode", "alert_only")
        )
        self.leak_checker = LeakChecker(
            trusted_dns=cfg.get("vpn_trusted_dns", [])
        )
        self.route_monitor = RouteMonitor()
        self.config_auditor = ConfigAuditor()

        self._tasks: list[asyncio.Task] = []
        self._event_queue: asyncio.Queue = asyncio.Queue()

    async def start(self) -> None:
        """Start all VPN monitoring sub-modules."""
        self.running = True
        self.health_status = "starting"
        logger.info("vpn_guardian_starting")

        # Initial VPN detection
        await self.detector.detect()
        state = self.detector.state

        if state.connected and state.interface_name:
            self.route_monitor.set_vpn_interface(state.interface_name)

        # Run initial config audit
        try:
            audit_report = self.config_auditor.run_audit()
            if audit_report.critical_count > 0:
                logger.warning(
                    "vpn_config_critical_issues",
                    count=audit_report.critical_count,
                )
        except Exception as e:
            logger.error("config_audit_failed", error=str(e))

        # Start monitoring tasks
        self._tasks.append(
            asyncio.create_task(
                self.detector.start_monitoring(on_change=self._on_vpn_state_change)
            )
        )

        if state.connected:
            self._tasks.append(
                asyncio.create_task(
                    self.leak_checker.start_monitoring(
                        expected_vpn_ip=state.vpn_ip,
                        on_leak=self._on_leak_detected,
                        interval=self.config.get("vpn_leak_check_interval", 60),
                    )
                )
            )

        self._tasks.append(
            asyncio.create_task(
                self.route_monitor.start_monitoring(on_change=self._on_route_change)
            )
        )

        self.health_status = "running"
        self.heartbeat()
        logger.info(
            "vpn_guardian_started",
            vpn_connected=state.connected,
            interface=state.interface_name,
            protocol=state.protocol,
        )

    async def stop(self) -> None:
        """Gracefully stop all monitoring and clean up."""
        logger.info("vpn_guardian_stopping")
        self.running = False

        # Stop sub-module monitoring loops
        self.detector.stop_monitoring()
        self.leak_checker.stop_monitoring()
        self.route_monitor.stop_monitoring()

        # Cancel async tasks
        for task in self._tasks:
            task.cancel()

        # Clean up kill switch rules
        await self.kill_switch.cleanup()

        self._tasks.clear()
        self.health_status = "stopped"
        logger.info("vpn_guardian_stopped")

    async def health_check(self) -> dict:
        """Return health status of VPN Guardian and sub-modules."""
        self.heartbeat()
        state = self.detector.state

        return {
            "status": self.health_status,
            "details": {
                "vpn_connected": state.connected,
                "vpn_protocol": state.protocol,
                "vpn_provider": state.provider,
                "vpn_interface": state.interface_name,
                "kill_switch_active": self.kill_switch.state.active,
                "kill_switch_mode": self.kill_switch.state.mode,
                "monitoring_tasks": len(self._tasks),
            },
        }

    async def _on_vpn_state_change(self, new_state: VPNState, old_state: VPNState) -> None:
        """Handle VPN connection state changes."""
        if old_state.connected and not new_state.connected:
            # VPN disconnected
            logger.warning("vpn_disconnected", interface=old_state.interface_name)

            # Activate kill switch
            vpn_server_ip = old_state.adapter_details.get("gateway")
            await self.kill_switch.activate(vpn_server_ip=vpn_server_ip)

            # Emit event
            await self._emit_event("vpn_disconnect", {
                "previous_interface": old_state.interface_name,
                "previous_ip": old_state.vpn_ip,
                "kill_switch_activated": self.kill_switch.state.active,
            })

        elif not old_state.connected and new_state.connected:
            # VPN connected
            logger.info(
                "vpn_connected",
                interface=new_state.interface_name,
                vpn_ip=new_state.vpn_ip,
                protocol=new_state.protocol,
            )

            # Deactivate kill switch
            await self.kill_switch.deactivate()

            # Update route monitor
            if new_state.interface_name:
                self.route_monitor.set_vpn_interface(new_state.interface_name)

            # Emit event
            await self._emit_event("vpn_connect", new_state.to_dict())

    async def _on_leak_detected(self, result) -> None:
        """Handle leak detection results."""
        logger.warning(
            "vpn_leak_detected",
            ip_leak=result.ip_leak,
            dns_leak=result.dns_leak,
            ipv6_leak=result.ipv6_leak,
        )

        await self._emit_event("vpn_leak", result.to_dict())

    async def _on_route_change(self, changes: list[dict]) -> None:
        """Handle routing table changes."""
        logger.info("route_changes", changes=changes)
        await self._emit_event("route_change", {"changes": changes})

    async def _emit_event(self, event_type: str, data: dict) -> None:
        """Emit an event for consumption by other modules or the API."""
        event = {
            "type": event_type,
            "module": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        await self._event_queue.put(event)
        logger.debug("event_emitted", event_type=event_type)

    async def get_status(self) -> dict:
        """Get comprehensive VPN status for the API."""
        state = self.detector.state
        return {
            "vpn": state.to_dict(),
            "kill_switch": {
                "active": self.kill_switch.state.active,
                "mode": self.kill_switch.state.mode,
            },
            "module": {
                "name": self.name,
                "running": self.running,
                "health": self.health_status,
            },
        }

    async def run_leak_check(self) -> dict:
        """Run an on-demand leak check."""
        state = self.detector.state
        result = await self.leak_checker.run_full_check(
            expected_vpn_ip=state.vpn_ip if state.connected else None,
        )
        return result.to_dict()

    def run_config_audit(self) -> dict:
        """Run an on-demand config audit."""
        report = self.config_auditor.run_audit()
        return report.to_dict()

    async def set_kill_switch_mode(self, mode: str) -> dict:
        """Change the kill switch mode."""
        self.kill_switch.set_mode(mode)
        return {"mode": mode, "active": self.kill_switch.state.active}
