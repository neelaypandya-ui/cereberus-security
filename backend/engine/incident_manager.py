"""Incident Manager — incident lifecycle management."""

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func as sa_func

from ..utils.logging import get_logger

logger = get_logger("engine.incident_manager")

VALID_TRANSITIONS = {
    "open": ["investigating", "closed"],
    "investigating": ["contained", "resolved", "closed"],
    "contained": ["resolved", "closed"],
    "resolved": ["closed", "open"],
    "closed": ["open"],
}


class IncidentManager:
    """Manages the full incident lifecycle."""

    def __init__(self, db_session_factory=None, ws_broadcast_fn=None):
        self._db_session_factory = db_session_factory
        self._ws_broadcast = ws_broadcast_fn

    def set_db_session_factory(self, factory) -> None:
        self._db_session_factory = factory

    def set_ws_broadcast(self, fn) -> None:
        self._ws_broadcast = fn

    async def _broadcast(self, event: str, data: dict) -> None:
        if self._ws_broadcast:
            try:
                await self._ws_broadcast({
                    "type": "incident_update",
                    "data": {"event": event, **data, "timestamp": datetime.now(timezone.utc).isoformat()},
                })
            except Exception:
                pass

    async def create_incident(
        self,
        title: str,
        severity: str,
        source_alert_ids: list[int] | None = None,
        category: str | None = None,
        description: str | None = None,
        created_by: str | None = None,
    ) -> dict:
        """Create a new incident."""
        from ..models.incident import Incident

        now = datetime.now(timezone.utc)
        timeline = [{"event": "created", "actor": created_by or "system", "timestamp": now.isoformat()}]

        async with self._db_session_factory() as session:
            incident = Incident(
                title=title,
                severity=severity,
                status="open",
                category=category,
                description=description,
                source_alert_ids_json=json.dumps(source_alert_ids) if source_alert_ids else None,
                timeline_json=json.dumps(timeline),
                created_by=created_by,
            )
            session.add(incident)
            await session.commit()
            await session.refresh(incident)
            result = self._to_dict(incident)

        await self._broadcast("created", result)
        logger.info("incident_created", id=result["id"], severity=severity, title=title)
        return result

    async def update_status(self, incident_id: int, new_status: str, actor: str = "system", note: str | None = None) -> dict:
        """Update incident status with transition validation."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            incident = (await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )).scalar_one_or_none()
            if not incident:
                return {"error": "Incident not found"}

            allowed = VALID_TRANSITIONS.get(incident.status, [])
            if new_status not in allowed:
                return {"error": f"Cannot transition from {incident.status} to {new_status}. Allowed: {allowed}"}

            old_status = incident.status
            incident.status = new_status
            incident.updated_at = datetime.now(timezone.utc)

            if new_status in ("resolved", "closed"):
                incident.resolved_at = datetime.now(timezone.utc)

            # Add timeline event
            timeline = json.loads(incident.timeline_json) if incident.timeline_json else []
            event = {
                "event": f"status_changed",
                "from": old_status,
                "to": new_status,
                "actor": actor,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if note:
                event["note"] = note
            timeline.append(event)
            incident.timeline_json = json.dumps(timeline)

            await session.commit()
            result = self._to_dict(incident)

        await self._broadcast("status_changed", result)
        logger.info("incident_status_updated", id=incident_id, old=old_status, new=new_status)
        return result

    async def add_timeline_event(self, incident_id: int, event: str, actor: str, details: str | None = None) -> dict:
        """Add a custom event to the incident timeline."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            incident = (await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )).scalar_one_or_none()
            if not incident:
                return {"error": "Incident not found"}

            timeline = json.loads(incident.timeline_json) if incident.timeline_json else []
            timeline.append({
                "event": event,
                "actor": actor,
                "details": details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            incident.timeline_json = json.dumps(timeline)
            incident.updated_at = datetime.now(timezone.utc)
            await session.commit()
            return self._to_dict(incident)

    async def assign_incident(self, incident_id: int, username: str, actor: str = "system") -> dict:
        """Assign an incident to a user."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            incident = (await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )).scalar_one_or_none()
            if not incident:
                return {"error": "Incident not found"}

            incident.assigned_to = username
            incident.updated_at = datetime.now(timezone.utc)

            timeline = json.loads(incident.timeline_json) if incident.timeline_json else []
            timeline.append({
                "event": "assigned",
                "assigned_to": username,
                "actor": actor,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            incident.timeline_json = json.dumps(timeline)
            await session.commit()
            result = self._to_dict(incident)

        await self._broadcast("assigned", result)
        return result

    async def link_remediation(self, incident_id: int, action_id: int) -> dict:
        """Link a remediation action to an incident."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            incident = (await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )).scalar_one_or_none()
            if not incident:
                return {"error": "Incident not found"}

            actions = json.loads(incident.remediation_actions_json) if incident.remediation_actions_json else []
            if action_id not in actions:
                actions.append(action_id)
            incident.remediation_actions_json = json.dumps(actions)
            incident.updated_at = datetime.now(timezone.utc)
            await session.commit()
            return self._to_dict(incident)

    async def add_note(self, incident_id: int, note: str, actor: str = "system") -> dict:
        """Add a note to an incident."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            incident = (await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )).scalar_one_or_none()
            if not incident:
                return {"error": "Incident not found"}

            existing = incident.notes or ""
            timestamp = datetime.now(timezone.utc).isoformat()
            incident.notes = f"{existing}\n[{timestamp}] {actor}: {note}".strip()
            incident.updated_at = datetime.now(timezone.utc)

            timeline = json.loads(incident.timeline_json) if incident.timeline_json else []
            timeline.append({
                "event": "note_added",
                "actor": actor,
                "note": note[:200],
                "timestamp": timestamp,
            })
            incident.timeline_json = json.dumps(timeline)
            await session.commit()
            return self._to_dict(incident)

    async def auto_create_from_correlation(self, correlation: dict, events: list[dict]) -> Optional[dict]:
        """Auto-create an incident from a threat correlation, with deduplication."""
        from ..models.incident import Incident

        pattern = correlation.get("pattern", "unknown")
        category = f"correlation_{pattern}"

        async with self._db_session_factory() as session:
            # Deduplicate: check for existing open incident with same category
            existing = (await session.execute(
                select(Incident).where(
                    Incident.category == category,
                    Incident.status.in_(["open", "investigating", "contained"]),
                )
            )).scalar_one_or_none()
            if existing:
                return None  # Already tracked

        severity = correlation.get("severity", "high")
        title = f"Auto-detected: {pattern.replace('_', ' ').title()}"
        description = correlation.get("description", f"Correlated pattern: {pattern}")

        alert_ids = [e.get("alert_id") for e in events if e.get("alert_id")]

        return await self.create_incident(
            title=title,
            severity=severity,
            source_alert_ids=alert_ids if alert_ids else None,
            category=category,
            description=description,
            created_by="threat_correlator",
        )

    async def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """List incidents with optional filters."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            query = select(Incident).order_by(Incident.created_at.desc()).limit(limit)
            if status:
                query = query.where(Incident.status == status)
            if severity:
                query = query.where(Incident.severity == severity)
            if assigned_to:
                query = query.where(Incident.assigned_to == assigned_to)
            result = await session.execute(query)
            return [self._to_dict(i) for i in result.scalars().all()]

    async def get_incident(self, incident_id: int) -> Optional[dict]:
        """Get a single incident by ID."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            incident = (await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )).scalar_one_or_none()
            return self._to_dict(incident) if incident else None

    async def get_stats(self) -> dict:
        """Get incident statistics."""
        from ..models.incident import Incident

        async with self._db_session_factory() as session:
            total = (await session.execute(select(sa_func.count(Incident.id)))).scalar() or 0
            by_status = {}
            for s in ["open", "investigating", "contained", "resolved", "closed"]:
                count = (await session.execute(
                    select(sa_func.count(Incident.id)).where(Incident.status == s)
                )).scalar() or 0
                by_status[s] = count
            by_severity = {}
            for s in ["critical", "high", "medium", "low"]:
                count = (await session.execute(
                    select(sa_func.count(Incident.id)).where(Incident.severity == s)
                )).scalar() or 0
                by_severity[s] = count
            return {"total": total, "by_status": by_status, "by_severity": by_severity}

    @staticmethod
    def _to_dict(incident) -> dict:
        return {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "category": incident.category,
            "assigned_to": incident.assigned_to,
            "source_alert_ids": json.loads(incident.source_alert_ids_json) if incident.source_alert_ids_json else [],
            "remediation_actions": json.loads(incident.remediation_actions_json) if incident.remediation_actions_json else [],
            "timeline": json.loads(incident.timeline_json) if incident.timeline_json else [],
            "notes": incident.notes,
            "created_by": incident.created_by,
            "created_at": incident.created_at.isoformat() if incident.created_at else None,
            "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        }
