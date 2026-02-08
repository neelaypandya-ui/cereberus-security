"""Playbook Executor — evaluates events against rules and triggers automated responses."""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from ..utils.logging import get_logger

logger = get_logger("engine.playbook_executor")


class PlaybookExecutor:
    """Evaluates security events against playbook rules and executes actions."""

    def __init__(self, db_session_factory=None, remediation_engine=None, ws_broadcast_fn=None):
        self._db_session_factory = db_session_factory
        self._remediation = remediation_engine
        self._ws_broadcast = ws_broadcast_fn
        self._rules_cache: list = []
        self._cache_timestamp: float = 0
        self._cache_ttl: float = 60.0  # Refresh every 60 seconds

    def set_db_session_factory(self, factory) -> None:
        self._db_session_factory = factory

    def set_remediation_engine(self, engine) -> None:
        self._remediation = engine

    def set_ws_broadcast(self, fn) -> None:
        self._ws_broadcast = fn

    async def _refresh_cache(self) -> None:
        """Load enabled playbook rules from DB."""
        import time
        now = time.time()
        if now - self._cache_timestamp < self._cache_ttl and self._rules_cache:
            return

        if not self._db_session_factory:
            return

        try:
            from ..models.playbook_rule import PlaybookRule
            async with self._db_session_factory() as session:
                result = await session.execute(
                    select(PlaybookRule).where(PlaybookRule.enabled == True)
                )
                rules = result.scalars().all()
                self._rules_cache = [self._rule_to_dict(r) for r in rules]
                self._cache_timestamp = now
        except Exception as e:
            logger.error("playbook_cache_refresh_failed", error=str(e))

    @staticmethod
    def _rule_to_dict(rule) -> dict:
        return {
            "id": rule.id,
            "name": rule.name,
            "trigger_type": rule.trigger_type,
            "trigger_conditions": json.loads(rule.trigger_conditions_json) if rule.trigger_conditions_json else {},
            "actions": json.loads(rule.actions_json) if rule.actions_json else [],
            "cooldown_seconds": rule.cooldown_seconds,
            "last_triggered": rule.last_triggered,
            "requires_confirmation": rule.requires_confirmation,
            "enabled": rule.enabled,
        }

    async def evaluate_event(self, event: dict) -> list[dict]:
        """Evaluate an event against all enabled playbook rules."""
        await self._refresh_cache()
        results = []

        for rule in self._rules_cache:
            if not rule["enabled"]:
                continue
            if self._is_in_cooldown(rule):
                continue
            if self._matches_trigger(rule, event):
                result = await self._execute_rule(rule, event)
                results.append(result)

        return results

    def _matches_trigger(self, rule: dict, event: dict) -> bool:
        """Check if an event matches a rule's trigger conditions."""
        trigger_type = rule["trigger_type"]
        conditions = rule["trigger_conditions"]

        if trigger_type == "alert_severity":
            severities = conditions.get("severity", [])
            return event.get("severity") in severities

        elif trigger_type == "anomaly_score":
            min_score = conditions.get("min_score", 0.7)
            return event.get("anomaly_score", 0) >= min_score

        elif trigger_type == "threat_level":
            levels = conditions.get("levels", [])
            return event.get("threat_level") in levels

        elif trigger_type == "correlation_pattern":
            pattern = conditions.get("pattern", "")
            return event.get("pattern") == pattern or event.get("event_type") == pattern

        elif trigger_type == "module_event":
            module = conditions.get("module", "")
            event_type = conditions.get("event_type", "")
            return (event.get("source_module") == module or event.get("module_source") == module) and \
                   (not event_type or event.get("event_type") == event_type)

        return False

    def _is_in_cooldown(self, rule: dict) -> bool:
        """Check if a rule is in cooldown period."""
        last = rule.get("last_triggered")
        if not last:
            return False
        if isinstance(last, str):
            last = datetime.fromisoformat(last)
        elapsed = (datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).total_seconds()
        return elapsed < rule.get("cooldown_seconds", 300)

    def _extract_action_params(self, action_def: dict, event: dict) -> dict:
        """Substitute template variables like $details.ip from event data."""
        result = {}
        for key, value in action_def.items():
            if isinstance(value, str) and value.startswith("$"):
                # Resolve $details.ip style references
                parts = value[1:].split(".")
                obj = event
                for part in parts:
                    if isinstance(obj, dict):
                        obj = obj.get(part, value)
                    else:
                        obj = value
                        break
                result[key] = obj
            else:
                result[key] = value
        return result

    async def _execute_rule(self, rule: dict, event: dict) -> dict:
        """Execute a playbook rule's actions."""
        rule_id = rule["id"]

        if rule["requires_confirmation"]:
            # Broadcast pending confirmation instead of executing
            if self._ws_broadcast:
                try:
                    await self._ws_broadcast({
                        "type": "playbook_trigger",
                        "data": {
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "status": "pending_confirmation",
                            "event": event,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    })
                except Exception:
                    pass
            logger.info("playbook_pending_confirmation", rule=rule["name"])
            return {"rule_id": rule_id, "status": "pending_confirmation", "actions": []}

        action_results = []
        for action_def in rule.get("actions", []):
            params = self._extract_action_params(action_def, event)
            action_type = params.get("type", "")
            result = await self._dispatch_action(action_type, params, rule_id=rule_id)
            action_results.append(result)

        # Update rule execution stats
        await self._update_rule_triggered(rule_id)

        if self._ws_broadcast:
            try:
                await self._ws_broadcast({
                    "type": "playbook_trigger",
                    "data": {
                        "rule_id": rule_id,
                        "rule_name": rule["name"],
                        "status": "executed",
                        "actions": action_results,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                })
            except Exception:
                pass

        logger.info("playbook_executed", rule=rule["name"], actions=len(action_results))
        return {"rule_id": rule_id, "status": "executed", "actions": action_results}

    async def _dispatch_action(self, action_type: str, params: dict, rule_id: int | None = None) -> dict:
        """Dispatch a single action to the remediation engine."""
        if not self._remediation:
            return {"action_type": action_type, "success": False, "error": "No remediation engine"}

        try:
            if action_type == "block_ip":
                return await self._remediation.block_ip(
                    ip=params.get("target", ""),
                    duration=params.get("duration", 3600),
                    reason=params.get("reason", f"Playbook rule {rule_id}"),
                    playbook_rule_id=rule_id,
                )
            elif action_type == "kill_process":
                return await self._remediation.kill_process(
                    target=params.get("target", ""),
                    playbook_rule_id=rule_id,
                )
            elif action_type == "quarantine_file":
                return await self._remediation.quarantine_file(
                    path=params.get("target", ""),
                    reason=params.get("reason", f"Playbook rule {rule_id}"),
                    playbook_rule_id=rule_id,
                )
            elif action_type == "isolate_network":
                return await self._remediation.isolate_network(
                    interface=params.get("target", ""),
                    playbook_rule_id=rule_id,
                )
            elif action_type == "disable_user":
                return await self._remediation.disable_user_account(
                    username=params.get("target", ""),
                    playbook_rule_id=rule_id,
                )
            else:
                return {"action_type": action_type, "success": False, "error": f"Unknown action: {action_type}"}
        except Exception as e:
            return {"action_type": action_type, "success": False, "error": str(e)}

    async def _update_rule_triggered(self, rule_id: int) -> None:
        """Update rule's last_triggered and execution_count."""
        if not self._db_session_factory:
            return
        try:
            from ..models.playbook_rule import PlaybookRule
            async with self._db_session_factory() as session:
                rule = (await session.execute(
                    select(PlaybookRule).where(PlaybookRule.id == rule_id)
                )).scalar_one_or_none()
                if rule:
                    rule.last_triggered = datetime.now(timezone.utc)
                    rule.execution_count = (rule.execution_count or 0) + 1
                    await session.commit()
        except Exception as e:
            logger.error("update_rule_triggered_failed", error=str(e))

    async def execute_playbook(self, rule_id: int, event_context: dict | None = None, dry_run: bool = False) -> dict:
        """Manually execute or test a specific playbook rule."""
        if not self._db_session_factory:
            return {"error": "No database session"}

        from ..models.playbook_rule import PlaybookRule
        async with self._db_session_factory() as session:
            rule = (await session.execute(
                select(PlaybookRule).where(PlaybookRule.id == rule_id)
            )).scalar_one_or_none()
            if not rule:
                return {"error": "Rule not found"}

            rule_dict = self._rule_to_dict(rule)

        if dry_run:
            actions_preview = []
            for action_def in rule_dict.get("actions", []):
                params = self._extract_action_params(action_def, event_context or {})
                actions_preview.append({"action_type": params.get("type"), "params": params, "dry_run": True})
            return {"rule_id": rule_id, "status": "dry_run", "actions": actions_preview}

        return await self._execute_rule(rule_dict, event_context or {})
