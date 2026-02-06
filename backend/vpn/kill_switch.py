"""Windows Firewall kill switch for VPN drop protection.

Uses netsh advfirewall to create/remove firewall rules that block
all outbound traffic when VPN connection drops, preventing IP leaks.
"""

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("vpn.kill_switch")

# Firewall rule name prefix for easy identification/cleanup
RULE_PREFIX = "Cereberus_KillSwitch"

# Local subnets to always allow (LAN access)
LOCAL_SUBNETS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
]


@dataclass
class KillSwitchState:
    """Current state of the kill switch."""
    active: bool = False
    mode: str = "alert_only"  # full, app_specific, alert_only
    activated_at: Optional[datetime] = None
    vpn_server_ip: Optional[str] = None
    blocked_apps: list[str] = None

    def __post_init__(self):
        if self.blocked_apps is None:
            self.blocked_apps = []


class KillSwitch:
    """Windows Firewall-based VPN kill switch.

    Modes:
        - full: Block ALL outbound except loopback, LAN, VPN server
        - app_specific: Block specific executables only
        - alert_only: No blocking, just generate alerts
    """

    def __init__(self, mode: str = "alert_only"):
        self._state = KillSwitchState(mode=mode)
        self._rules_created: list[str] = []

    @property
    def state(self) -> KillSwitchState:
        return self._state

    def _run_netsh(self, args: list[str]) -> tuple[bool, str]:
        """Execute a netsh command. Returns (success, output)."""
        cmd = ["netsh"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            success = result.returncode == 0
            output = result.stdout + result.stderr
            if not success:
                logger.warning("netsh_command_failed", cmd=" ".join(cmd), output=output)
            return success, output
        except subprocess.TimeoutExpired:
            logger.error("netsh_command_timeout", cmd=" ".join(cmd))
            return False, "timeout"
        except FileNotFoundError:
            logger.error("netsh_not_found")
            return False, "netsh not found"

    def _create_block_rule(self, rule_name: str, direction: str = "out") -> bool:
        """Create a firewall rule that blocks all traffic."""
        success, _ = self._run_netsh([
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            "enable=yes",
            "profile=any",
            "protocol=any",
        ])
        if success:
            self._rules_created.append(rule_name)
        return success

    def _create_allow_rule(
        self,
        rule_name: str,
        remote_ip: str,
        direction: str = "out",
        protocol: str = "any",
    ) -> bool:
        """Create a firewall rule that allows traffic to specific IPs."""
        success, _ = self._run_netsh([
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=allow",
            "enable=yes",
            "profile=any",
            f"protocol={protocol}",
            f"remoteip={remote_ip}",
        ])
        if success:
            self._rules_created.append(rule_name)
        return success

    def _create_app_block_rule(self, rule_name: str, exe_path: str) -> bool:
        """Block a specific application's outbound traffic."""
        success, _ = self._run_netsh([
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            "enable=yes",
            "profile=any",
            f"program={exe_path}",
        ])
        if success:
            self._rules_created.append(rule_name)
        return success

    def _delete_rule(self, rule_name: str) -> bool:
        """Delete a firewall rule by name."""
        success, _ = self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ])
        return success

    async def activate(self, vpn_server_ip: Optional[str] = None) -> bool:
        """Activate the kill switch.

        Args:
            vpn_server_ip: The VPN server's real IP to allow reconnection.

        Returns:
            True if successfully activated.
        """
        if self._state.mode == "alert_only":
            logger.info("kill_switch_alert_mode", message="VPN dropped - alert only mode")
            self._state.active = True
            self._state.activated_at = datetime.now(timezone.utc)
            return True

        if self._state.mode == "app_specific":
            return await self._activate_app_specific()

        # Full kill switch mode
        logger.warning("kill_switch_activating", mode="full", vpn_server=vpn_server_ip)
        self._state.vpn_server_ip = vpn_server_ip

        # Step 1: Allow loopback and LAN
        for i, subnet in enumerate(LOCAL_SUBNETS):
            self._create_allow_rule(
                f"{RULE_PREFIX}_Allow_Local_{i}",
                subnet,
            )

        # Step 2: Allow VPN server IP (for reconnection)
        if vpn_server_ip:
            self._create_allow_rule(
                f"{RULE_PREFIX}_Allow_VPN_Server",
                vpn_server_ip,
            )

        # Step 3: Block everything else outbound
        self._create_block_rule(f"{RULE_PREFIX}_Block_All_Out")

        self._state.active = True
        self._state.activated_at = datetime.now(timezone.utc)
        logger.warning("kill_switch_activated", rules_created=len(self._rules_created))
        return True

    async def _activate_app_specific(self) -> bool:
        """Activate kill switch for specific applications only."""
        logger.info(
            "kill_switch_app_specific",
            apps=self._state.blocked_apps,
        )
        for i, app_path in enumerate(self._state.blocked_apps):
            self._create_app_block_rule(
                f"{RULE_PREFIX}_Block_App_{i}",
                app_path,
            )
        self._state.active = True
        self._state.activated_at = datetime.now(timezone.utc)
        return True

    async def deactivate(self) -> bool:
        """Deactivate the kill switch and remove all created firewall rules."""
        if not self._state.active:
            return True

        logger.info("kill_switch_deactivating", rules_to_remove=len(self._rules_created))

        # Remove all rules we created
        for rule_name in list(self._rules_created):
            self._delete_rule(rule_name)

        self._rules_created.clear()
        self._state.active = False
        self._state.activated_at = None
        logger.info("kill_switch_deactivated")
        return True

    async def cleanup(self) -> None:
        """Emergency cleanup: remove ALL Cereberus firewall rules."""
        logger.warning("kill_switch_emergency_cleanup")
        # Delete any rule matching our prefix pattern
        self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name={RULE_PREFIX}_Block_All_Out",
        ])
        for i in range(len(LOCAL_SUBNETS)):
            self._run_netsh([
                "advfirewall", "firewall", "delete", "rule",
                f"name={RULE_PREFIX}_Allow_Local_{i}",
            ])
        self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name={RULE_PREFIX}_Allow_VPN_Server",
        ])
        for i in range(20):  # Clean up to 20 app rules
            self._run_netsh([
                "advfirewall", "firewall", "delete", "rule",
                f"name={RULE_PREFIX}_Block_App_{i}",
            ])
        self._rules_created.clear()
        self._state.active = False

    def set_mode(self, mode: str) -> None:
        """Change the kill switch mode."""
        if mode not in {"full", "app_specific", "alert_only"}:
            raise ValueError(f"Invalid mode: {mode}")
        self._state.mode = mode
        logger.info("kill_switch_mode_changed", mode=mode)

    def add_blocked_app(self, exe_path: str) -> None:
        """Add an application to the app-specific block list."""
        if exe_path not in self._state.blocked_apps:
            self._state.blocked_apps.append(exe_path)
