"""Export routes — async data export with background processing."""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db, get_app_config
from ...auth.rbac import require_permission, PERM_EXPORT_DATA
from ...models.export_job import ExportJob


router = APIRouter(prefix="/export", tags=["export"])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXPORT_DIR = Path("data/exports")
VALID_EXPORT_TYPES = ("alerts", "incidents", "audit", "full_report", "iocs")
VALID_FORMATS = ("csv", "json")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class ExportRequest(BaseModel):
    export_type: str  # alerts, incidents, audit, full_report, iocs
    format: str  # csv, json, pdf
    filters: dict | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _job_to_dict(job: ExportJob) -> dict:
    return {
        "id": job.id,
        "export_type": job.export_type,
        "format": job.format,
        "filters": json.loads(job.filters_json) if job.filters_json else {},
        "status": job.status,
        "file_path": job.file_path,
        "requested_by": job.requested_by,
        "requested_at": job.requested_at.isoformat() if job.requested_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "file_size_bytes": job.file_size_bytes,
        "error_message": job.error_message,
    }


async def _run_export(job_id: int) -> None:
    """Background task that performs the actual export."""
    from ...database import get_session_factory
    config = get_app_config()
    factory = get_session_factory(config)

    async with factory() as db:
        result = await db.execute(select(ExportJob).where(ExportJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            return

        job.status = "processing"
        await db.commit()

        try:
            # Ensure export directory exists
            EXPORT_DIR.mkdir(parents=True, exist_ok=True)

            export_type = job.export_type
            export_format = job.format
            filters = json.loads(job.filters_json) if job.filters_json else {}

            filename = f"{export_type}_{job.id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.{export_format}"
            file_path = EXPORT_DIR / filename

            data = await _collect_export_data(db, export_type, filters)

            if export_format == "json":
                content = json.dumps(data, indent=2, default=str)
                file_path.write_text(content, encoding="utf-8")
            elif export_format == "csv":
                content = _to_csv(data)
                file_path.write_text(content, encoding="utf-8")

            file_size = file_path.stat().st_size

            job.status = "completed"
            job.file_path = str(file_path)
            job.completed_at = datetime.now(timezone.utc)
            job.file_size_bytes = file_size
            await db.commit()

        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()


async def _collect_export_data(db: AsyncSession, export_type: str, filters: dict) -> list[dict]:
    """Collect data based on export type and filters."""
    if export_type == "alerts":
        from ...models.alert import Alert
        query = select(Alert).order_by(Alert.timestamp.desc())
        limit = filters.get("limit", 1000)
        query = query.limit(limit)
        if filters.get("severity"):
            query = query.where(Alert.severity == filters["severity"])
        result = await db.execute(query)
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "severity": r.severity,
                "module_source": r.module_source,
                "title": r.title,
                "description": r.description,
                "acknowledged": r.acknowledged,
            }
            for r in rows
        ]

    elif export_type == "iocs":
        from ...models.ioc import IOC
        query = select(IOC).order_by(IOC.first_seen.desc())
        limit = filters.get("limit", 5000)
        query = query.limit(limit)
        if filters.get("ioc_type"):
            query = query.where(IOC.ioc_type == filters["ioc_type"])
        if filters.get("active") is not None:
            query = query.where(IOC.active == filters["active"])
        result = await db.execute(query)
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "ioc_type": r.ioc_type,
                "value": r.value,
                "source": r.source,
                "severity": r.severity,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "active": r.active,
            }
            for r in rows
        ]

    elif export_type == "audit":
        from ...models.audit_log import AuditLog
        query = select(AuditLog).order_by(AuditLog.timestamp.desc())
        limit = filters.get("limit", 1000)
        query = query.limit(limit)
        result = await db.execute(query)
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "user": r.user,
                "action": r.action,
                "resource": r.resource,
                "details": r.details,
            }
            for r in rows
        ]

    elif export_type == "incidents":
        from ...models.incident import Incident
        query = select(Incident).order_by(Incident.created_at.desc())
        limit = filters.get("limit", 500)
        query = query.limit(limit)
        result = await db.execute(query)
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    elif export_type == "full_report":
        # Combine alerts + IOCs
        alerts_data = await _collect_export_data(db, "alerts", filters)
        iocs_data = await _collect_export_data(db, "iocs", filters)
        return [
            {"section": "alerts", "data": alerts_data},
            {"section": "iocs", "data": iocs_data},
        ]

    return []


def _to_csv(data: list[dict]) -> str:
    """Convert a list of flat dicts to CSV string."""
    if not data:
        return ""

    # Handle nested full_report structure
    if data and isinstance(data[0].get("data"), list):
        lines = []
        for section in data:
            section_name = section.get("section", "unknown")
            section_data = section.get("data", [])
            lines.append(f"# Section: {section_name}")
            if section_data:
                headers = list(section_data[0].keys())
                lines.append(",".join(headers))
                for row in section_data:
                    values = [str(row.get(h, "")).replace(",", ";").replace("\n", " ") for h in headers]
                    lines.append(",".join(values))
            lines.append("")
        return "\n".join(lines)

    headers = list(data[0].keys())
    lines = [",".join(headers)]
    for row in data:
        values = [str(row.get(h, "")).replace(",", ";").replace("\n", " ") for h in headers]
        lines.append(",".join(values))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/", status_code=status.HTTP_202_ACCEPTED)
async def request_export(
    body: ExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """Request a data export — creates a job and launches background processing."""
    if body.export_type not in VALID_EXPORT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"export_type must be one of {VALID_EXPORT_TYPES}",
        )
    if body.format not in VALID_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"format must be one of {VALID_FORMATS}",
        )

    job = ExportJob(
        export_type=body.export_type,
        format=body.format,
        filters_json=json.dumps(body.filters) if body.filters else None,
        status="pending",
        requested_by=current_user.get("sub", "unknown"),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Launch background export task
    asyncio.create_task(_run_export(job.id))

    return _job_to_dict(job)


@router.get("/")
async def list_export_jobs(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """List all export jobs."""
    result = await db.execute(
        select(ExportJob).order_by(ExportJob.requested_at.desc()).limit(100)
    )
    rows = result.scalars().all()
    return [_job_to_dict(j) for j in rows]


@router.get("/{job_id}")
async def get_export_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """Get the status of an export job."""
    result = await db.execute(select(ExportJob).where(ExportJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")
    return _job_to_dict(job)


@router.get("/{job_id}/download")
async def download_export(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """Download the exported file."""
    result = await db.execute(select(ExportJob).where(ExportJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")

    if job.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Export is not ready — current status: {job.status}",
        )

    if not job.file_path or not os.path.isfile(job.file_path):
        raise HTTPException(status_code=404, detail="Export file not found on disk")

    # Determine media type
    media_types = {
        "csv": "text/csv",
        "json": "application/json",
        "pdf": "application/pdf",
    }
    media_type = media_types.get(job.format, "application/octet-stream")
    filename = os.path.basename(job.file_path)

    return FileResponse(
        path=job.file_path,
        media_type=media_type,
        filename=filename,
    )


@router.delete("/{job_id}")
async def delete_export_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """Delete an export job and its associated file."""
    result = await db.execute(select(ExportJob).where(ExportJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")

    # Remove file from disk if it exists
    if job.file_path and os.path.isfile(job.file_path):
        try:
            os.remove(job.file_path)
        except OSError:
            pass  # Best effort — file may already be gone

    await db.delete(job)
    await db.commit()
    return {"deleted": job_id}
