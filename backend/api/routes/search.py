"""Global search routes — searches across alerts, processes, connections, vulnerabilities."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import (
    get_db,
    get_network_sentinel,
    get_process_analyzer,
    get_vuln_scanner,
)
from ...models.alert import Alert

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
async def global_search(
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Search across alerts, processes, connections, and vulnerabilities."""
    query_lower = q.lower()

    # Search alerts in DB
    result = await db.execute(
        select(Alert)
        .where(
            or_(
                Alert.title.ilike(f"%{q}%"),
                Alert.description.ilike(f"%{q}%"),
            )
        )
        .order_by(Alert.timestamp.desc())
        .limit(limit)
    )
    alert_rows = result.scalars().all()
    alerts = [
        {
            "id": a.id,
            "severity": a.severity,
            "title": a.title,
            "module_source": a.module_source,
            "timestamp": a.timestamp.isoformat(),
        }
        for a in alert_rows
    ]

    # Search processes (in-memory)
    processes = []
    try:
        pa = get_process_analyzer()
        all_procs = pa.get_processes() if hasattr(pa, "get_processes") else []
        for p in all_procs:
            name = (p.get("name") or "").lower()
            exe = (p.get("exe") or "").lower()
            if query_lower in name or query_lower in exe:
                processes.append(p)
                if len(processes) >= limit:
                    break
    except Exception:
        pass

    # Search connections (in-memory)
    connections = []
    try:
        ns = get_network_sentinel()
        all_conns = ns.get_live_connections()
        for c in all_conns:
            remote = (c.get("remote_addr") or "").lower()
            if query_lower in remote:
                connections.append(c)
                if len(connections) >= limit:
                    break
    except Exception:
        pass

    # Search vulnerabilities (in-memory)
    vulnerabilities = []
    try:
        vs = get_vuln_scanner()
        all_vulns = vs.get_vulnerabilities()
        for v in all_vulns:
            title = (v.get("title") or "").lower()
            desc = (v.get("description") or "").lower()
            if query_lower in title or query_lower in desc:
                vulnerabilities.append(v)
                if len(vulnerabilities) >= limit:
                    break
    except Exception:
        pass

    total_count = len(alerts) + len(processes) + len(connections) + len(vulnerabilities)

    return {
        "query": q,
        "results": {
            "alerts": alerts,
            "processes": processes,
            "connections": connections,
            "vulnerabilities": vulnerabilities,
        },
        "total_count": total_count,
    }
