"""Remediation Engine — executes OS-level security actions."""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..utils.input_validators import (
    sanitize_firewall_rule_name,
    validate_file_path,
    validate_interface_name,
    validate_ip_address,
    validate_port,
    validate_process_target,
    validate_protocol,
    validate_username,
)
from ..utils.logging import get_logger

logger = get_logger("engine.remediation")


def _run_cmd(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a subprocess with argument list (never shell=True)."""
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


class RemediationEngine:
    """Executes OS-level remediation actions and logs results."""

    def __init__(self, db_session_factory=None, base_dir: str = ".", ws_broadcast_fn=None):
        self._db_session_factory = db_session_factory
        self._base_dir = Path(base_dir)
        self._vault_dir = self._base_dir / "quarantine_vault"
        self._ws_broadcast = ws_broadcast_fn

    def set_db_session_factory(self, factory) -> None:
        self._db_session_factory = factory

    def set_ws_broadcast(self, fn) -> None:
        self._ws_broadcast = fn

    async def _persist_action(
        self,
        action_type: str,
        target: str,
        status: str,
        parameters: dict | None = None,
        result: dict | None = None,
        rollback_data: dict | None = None,
        incident_id: int | None = None,
        playbook_rule_id: int | None = None,
        executed_by: str | None = None,
    ) -> int | None:
        """Persist a remediation action to the database."""
        if not self._db_session_factory:
            return None
        try:
            from ..models.remediation_action import RemediationAction

            now = datetime.now(timezone.utc)
            async with self._db_session_factory() as session:
                action = RemediationAction(
                    action_type=action_type,
                    target=target,
                    status=status,
                    parameters_json=json.dumps(parameters) if parameters else None,
                    result_json=json.dumps(result) if result else None,
                    rollback_data_json=json.dumps(rollback_data) if rollback_data else None,
                    incident_id=incident_id,
                    playbook_rule_id=playbook_rule_id,
                    executed_by=executed_by,
                    executed_at=now if status != "pending" else None,
                    completed_at=now if status in ("completed", "failed") else None,
                )
                session.add(action)
                await session.commit()
                await session.refresh(action)
                action_id = action.id
            return action_id
        except Exception as e:
            logger.error("persist_action_failed", error=str(e))
            return None

    async def _update_action_status(self, action_id: int, status: str, result: dict | None = None) -> None:
        if not self._db_session_factory or not action_id:
            return
        try:
            from ..models.remediation_action import RemediationAction
            from sqlalchemy import select

            async with self._db_session_factory() as session:
                stmt = select(RemediationAction).where(RemediationAction.id == action_id)
                row = (await session.execute(stmt)).scalar_one_or_none()
                if row:
                    row.status = status
                    if result:
                        row.result_json = json.dumps(result)
                    if status in ("completed", "failed", "rolled_back"):
                        row.completed_at = datetime.now(timezone.utc)
                    await session.commit()
        except Exception as e:
            logger.error("update_action_status_failed", error=str(e))

    async def _broadcast(self, action_type: str, target: str, status: str, details: dict | None = None) -> None:
        if self._ws_broadcast:
            try:
                await self._ws_broadcast({
                    "type": "remediation_action",
                    "data": {
                        "action_type": action_type,
                        "target": target,
                        "status": status,
                        "details": details or {},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                })
            except Exception:
                pass

    async def block_ip(
        self, ip: str, duration: int = 3600, reason: str = "",
        incident_id: int | None = None, playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Block an IP address using Windows Firewall."""
        try:
            ip = validate_ip_address(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        rule_name = sanitize_firewall_rule_name(f"CEREBERUS_REMEDIATION_{ip.replace('.', '_').replace(':', '_')}")
        action_id = await self._persist_action(
            "block_ip", ip, "executing",
            parameters={"duration": duration, "reason": reason, "rule_name": rule_name},
            rollback_data={"rule_name": rule_name},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip}", "protocol=any",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip()}
            status = "completed" if success else "failed"
            await self._update_action_status(action_id, status, res)
            await self._broadcast("block_ip", ip, status, res)
            logger.info("block_ip", ip=ip, success=success)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def unblock_ip(self, ip: str, executed_by: str | None = None) -> dict:
        """Remove firewall rule for an IP."""
        try:
            ip = validate_ip_address(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        rule_name = sanitize_firewall_rule_name(f"CEREBERUS_REMEDIATION_{ip.replace('.', '_').replace(':', '_')}")
        action_id = await self._persist_action(
            "block_ip", ip, "executing",
            parameters={"action": "unblock", "rule_name": rule_name},
            executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip()}
            await self._update_action_status(action_id, "completed" if success else "failed", res)
            await self._broadcast("unblock_ip", ip, "completed" if success else "failed", res)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def kill_process(
        self, target: str, incident_id: int | None = None,
        playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Kill a process by PID or name."""
        try:
            target = validate_process_target(target)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        action_id = await self._persist_action(
            "kill_process", target, "executing",
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            import psutil
            killed = []
            if target.isdigit():
                pid = int(target)
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.terminate()
                killed.append({"pid": pid, "name": proc_name})
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: _run_cmd(["taskkill", "/F", "/IM", target])
                )
                killed.append({"name": target, "output": result.stdout.strip()})

            res = {"success": True, "killed": killed}
            await self._update_action_status(action_id, "completed", res)
            await self._broadcast("kill_process", target, "completed", res)
            logger.info("kill_process", target=target, killed=len(killed))
            return {"action_id": action_id, **res}
        except Exception as e:
            res = {"success": False, "error": str(e)}
            await self._update_action_status(action_id, "failed", res)
            return {"action_id": action_id, **res}

    async def quarantine_file(
        self, path: str, reason: str = "",
        incident_id: int | None = None, playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Quarantine a file — hash, move to vault, write stub."""
        try:
            path = validate_file_path(path)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        action_id = await self._persist_action(
            "quarantine_file", path, "executing",
            parameters={"reason": reason},
            rollback_data={"original_path": path},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            src = Path(path)
            if not src.exists():
                raise FileNotFoundError(f"File not found: {path}")

            # Compute SHA-256
            sha256 = hashlib.sha256()
            file_size = src.stat().st_size
            with open(src, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            # Create vault dir
            self._vault_dir.mkdir(parents=True, exist_ok=True)
            vault_path = self._vault_dir / f"{file_hash}_{src.name}"

            # Move file to vault
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: shutil.move(str(src), str(vault_path))
            )

            # Write stub at original location
            with open(src, "w") as f:
                f.write(f"[QUARANTINED BY CEREBERUS]\nOriginal: {path}\nHash: {file_hash}\nReason: {reason}\n")

            # Persist to quarantine_vault table
            if self._db_session_factory:
                from ..models.quarantine_vault import QuarantineEntry
                async with self._db_session_factory() as session:
                    entry = QuarantineEntry(
                        original_path=path,
                        vault_path=str(vault_path),
                        file_hash=file_hash,
                        file_size=file_size,
                        quarantined_by=executed_by,
                        reason=reason,
                        incident_id=incident_id,
                    )
                    session.add(entry)
                    await session.commit()

            res = {"success": True, "file_hash": file_hash, "vault_path": str(vault_path), "file_size": file_size}
            await self._update_action_status(action_id, "completed", res)
            await self._broadcast("quarantine_file", path, "completed", res)
            logger.info("quarantine_file", path=path, hash=file_hash)
            return {"action_id": action_id, **res}
        except Exception as e:
            res = {"success": False, "error": str(e)}
            await self._update_action_status(action_id, "failed", res)
            return {"action_id": action_id, **res}

    async def restore_file(self, quarantine_id: int, executed_by: str | None = None) -> dict:
        """Restore a quarantined file."""
        try:
            from ..models.quarantine_vault import QuarantineEntry
            from sqlalchemy import select

            if not self._db_session_factory:
                return {"success": False, "error": "No database session"}

            async with self._db_session_factory() as session:
                entry = (await session.execute(
                    select(QuarantineEntry).where(QuarantineEntry.id == quarantine_id)
                )).scalar_one_or_none()

                if not entry:
                    return {"success": False, "error": "Quarantine entry not found"}
                if entry.status != "quarantined":
                    return {"success": False, "error": f"Entry status is {entry.status}"}

                vault_path = Path(entry.vault_path)
                original_path = Path(entry.original_path)

                if not vault_path.exists():
                    return {"success": False, "error": "Vault file missing"}

                # Remove stub if it exists
                if original_path.exists():
                    os.remove(str(original_path))

                # Move file back
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: shutil.move(str(vault_path), str(original_path))
                )

                entry.status = "restored"
                entry.restored_at = datetime.now(timezone.utc)
                await session.commit()

            await self._broadcast("restore_file", str(original_path), "completed")
            logger.info("restore_file", quarantine_id=quarantine_id)
            return {"success": True, "restored_path": str(original_path)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def isolate_network(
        self, interface: str, incident_id: int | None = None,
        playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Disable a network interface to isolate the system."""
        try:
            interface = validate_interface_name(interface)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        action_id = await self._persist_action(
            "isolate_network", interface, "executing",
            rollback_data={"interface": interface},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "interface", "set", "interface",
                    interface, "admin=disable",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip()}
            await self._update_action_status(action_id, "completed" if success else "failed", res)
            await self._broadcast("isolate_network", interface, "completed" if success else "failed", res)
            logger.info("isolate_network", interface=interface, success=success)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def restore_network(self, interface: str, executed_by: str | None = None) -> dict:
        """Re-enable a network interface."""
        try:
            interface = validate_interface_name(interface)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        action_id = await self._persist_action(
            "isolate_network", interface, "executing",
            parameters={"action": "restore"},
            executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "interface", "set", "interface",
                    interface, "admin=enable",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip()}
            await self._update_action_status(action_id, "completed" if success else "failed", res)
            await self._broadcast("restore_network", interface, "completed" if success else "failed", res)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def disable_user_account(
        self, username: str, incident_id: int | None = None,
        playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Disable a Windows user account."""
        try:
            username = validate_username(username)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        action_id = await self._persist_action(
            "disable_user", username, "executing",
            rollback_data={"username": username},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd(["net", "user", username, "/active:no"])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip()}
            await self._update_action_status(action_id, "completed" if success else "failed", res)
            await self._broadcast("disable_user", username, "completed" if success else "failed", res)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def block_port(
        self, port: int, protocol: str = "TCP",
        incident_id: int | None = None, playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Block an inbound port using Windows Firewall."""
        try:
            port = validate_port(port)
            protocol = validate_protocol(protocol)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        rule_name = sanitize_firewall_rule_name(f"CEREBERUS_BLOCK_PORT_{port}")

        # Check if rule already exists to avoid duplicates
        try:
            check_result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "advfirewall", "firewall", "show", "rule",
                    f"name={rule_name}",
                ], timeout=5)
            )
            if check_result.returncode == 0 and "Action:" in check_result.stdout:
                return {"action_id": None, "success": True, "output": f"Firewall rule {rule_name} already exists", "rule_name": rule_name, "already_exists": True}
        except Exception:
            pass  # If check fails, proceed with creation attempt

        action_id = await self._persist_action(
            "block_port", str(port), "executing",
            parameters={"port": port, "protocol": protocol, "rule_name": rule_name},
            rollback_data={"rule_name": rule_name, "port": port},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"localport={port}", f"protocol={protocol}",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip(), "rule_name": rule_name}
            status = "completed" if success else "failed"
            await self._update_action_status(action_id, status, res)
            await self._broadcast("block_port", str(port), status, res)
            logger.info("block_port", port=port, protocol=protocol, success=success)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def disable_guest_account(
        self, incident_id: int | None = None, playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Disable the Windows guest account."""
        action_id = await self._persist_action(
            "disable_guest", "guest", "executing",
            rollback_data={"username": "guest"},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd(["net", "user", "guest", "/active:no"])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip()}
            status = "completed" if success else "failed"
            await self._update_action_status(action_id, status, res)
            await self._broadcast("disable_guest", "guest", status, res)
            logger.info("disable_guest_account", success=success)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def enable_firewall(
        self, incident_id: int | None = None, playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Enable Windows Firewall on all profiles."""
        action_id = await self._persist_action(
            "enable_firewall", "all_profiles", "executing",
            rollback_data={"action": "disable_firewall"},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "netsh", "advfirewall", "set", "allprofiles", "state", "on",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip()}
            status = "completed" if success else "failed"
            await self._update_action_status(action_id, status, res)
            await self._broadcast("enable_firewall", "all_profiles", status, res)
            logger.info("enable_firewall", success=success)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def disable_autologin(
        self, incident_id: int | None = None, playbook_rule_id: int | None = None, executed_by: str | None = None,
    ) -> dict:
        """Disable Windows auto-login by setting AutoAdminLogon to 0."""
        action_id = await self._persist_action(
            "disable_autologin", "AutoAdminLogon", "executing",
            rollback_data={"action": "enable_autologin"},
            incident_id=incident_id, playbook_rule_id=playbook_rule_id, executed_by=executed_by,
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _run_cmd([
                    "reg", "add",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    "/v", "AutoAdminLogon", "/t", "REG_SZ", "/d", "0", "/f",
                ])
            )
            success = result.returncode == 0
            res = {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip()}
            status = "completed" if success else "failed"
            await self._update_action_status(action_id, status, res)
            await self._broadcast("disable_autologin", "AutoAdminLogon", status, res)
            logger.info("disable_autologin", success=success)
            return {"action_id": action_id, **res}
        except Exception as e:
            await self._update_action_status(action_id, "failed", {"error": str(e)})
            return {"action_id": action_id, "success": False, "error": str(e)}

    async def rollback_action(self, action_id: int, executed_by: str | None = None) -> dict:
        """Rollback a previously executed remediation action."""
        if not self._db_session_factory:
            return {"success": False, "error": "No database session"}

        try:
            from ..models.remediation_action import RemediationAction
            from sqlalchemy import select

            async with self._db_session_factory() as session:
                action = (await session.execute(
                    select(RemediationAction).where(RemediationAction.id == action_id)
                )).scalar_one_or_none()

                if not action:
                    return {"success": False, "error": "Action not found"}
                if action.status != "completed":
                    return {"success": False, "error": f"Cannot rollback action with status: {action.status}"}

                rollback_data = json.loads(action.rollback_data_json) if action.rollback_data_json else {}
                if not rollback_data:
                    return {"success": False, "error": "No rollback data available"}

                result = {"success": False, "error": "Unknown action type"}

                if action.action_type == "block_ip":
                    rule_name = sanitize_firewall_rule_name(rollback_data.get("rule_name", ""))
                    if rule_name:
                        proc = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: _run_cmd([
                                "netsh", "advfirewall", "firewall", "delete", "rule",
                                f"name={rule_name}",
                            ])
                        )
                        result = {"success": proc.returncode == 0, "output": proc.stdout.strip()}

                elif action.action_type == "isolate_network":
                    interface = rollback_data.get("interface", "")
                    if interface:
                        result = await self.restore_network(interface, executed_by=executed_by)

                elif action.action_type == "disable_user":
                    username = rollback_data.get("username", "")
                    if username:
                        try:
                            username = validate_username(username)
                        except ValueError as e:
                            return {"success": False, "error": str(e)}
                        proc = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: _run_cmd(["net", "user", username, "/active:yes"])
                        )
                        result = {"success": proc.returncode == 0, "output": proc.stdout.strip()}

                elif action.action_type == "quarantine_file":
                    original_path = rollback_data.get("original_path", "")
                    if original_path:
                        # Find quarantine entry and restore
                        from ..models.quarantine_vault import QuarantineEntry
                        qe = (await session.execute(
                            select(QuarantineEntry).where(
                                QuarantineEntry.original_path == original_path,
                                QuarantineEntry.status == "quarantined",
                            )
                        )).scalar_one_or_none()
                        if qe:
                            result = await self.restore_file(qe.id, executed_by=executed_by)
                        else:
                            result = {"success": False, "error": "Quarantine entry not found"}

                elif action.action_type == "block_port":
                    rule_name = sanitize_firewall_rule_name(rollback_data.get("rule_name", ""))
                    if rule_name:
                        proc = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: _run_cmd([
                                "netsh", "advfirewall", "firewall", "delete", "rule",
                                f"name={rule_name}",
                            ])
                        )
                        result = {"success": proc.returncode == 0, "output": proc.stdout.strip()}

                elif action.action_type == "disable_guest":
                    username = rollback_data.get("username", "guest")
                    proc = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: _run_cmd(["net", "user", username, "/active:yes"])
                    )
                    result = {"success": proc.returncode == 0, "output": proc.stdout.strip()}

                elif action.action_type == "enable_firewall":
                    proc = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: _run_cmd([
                            "netsh", "advfirewall", "set", "allprofiles", "state", "off",
                        ])
                    )
                    result = {"success": proc.returncode == 0, "output": proc.stdout.strip()}

                elif action.action_type == "disable_autologin":
                    proc = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: _run_cmd([
                            "reg", "add",
                            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                            "/v", "AutoAdminLogon", "/t", "REG_SZ", "/d", "1", "/f",
                        ])
                    )
                    result = {"success": proc.returncode == 0, "output": proc.stdout.strip()}

                if result.get("success"):
                    action.status = "rolled_back"
                    action.completed_at = datetime.now(timezone.utc)
                    await session.commit()
                    await self._broadcast("rollback", action.target, "completed", result)

                return result
        except Exception as e:
            return {"success": False, "error": str(e)}
