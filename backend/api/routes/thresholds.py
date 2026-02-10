"""Runtime threshold configuration API."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_MANAGE_SETTINGS, PERM_VIEW_DASHBOARD
from ...bridge import validate_and_log, ThresholdResponse
from ...dependencies import get_db, get_app_config

router = APIRouter(prefix="/thresholds", tags=["thresholds"])

# Define all configurable thresholds with metadata
THRESHOLD_REGISTRY = {
    "exfil_bytes_threshold": {
        "category": "detection",
        "description": "Bytes transferred before triggering exfiltration alert",
        "default": 10_000_000,
        "type": "int",
    },
    "anomaly_cooldown_minutes": {
        "category": "detection",
        "description": "Minutes between repeated anomaly alerts",
        "default": 30,
        "type": "int",
    },
    "ioc_cache_ttl": {
        "category": "ioc",
        "description": "IOC cache time-to-live in seconds",
        "default": 300,
        "type": "int",
    },
    "ioc_cache_max_size": {
        "category": "ioc",
        "description": "Maximum number of IOCs to cache in memory",
        "default": 10000,
        "type": "int",
    },
    "vt_severity_critical_threshold": {
        "category": "intel",
        "description": "VirusTotal detections for critical severity",
        "default": 10,
        "type": "int",
    },
    "vt_severity_high_threshold": {
        "category": "intel",
        "description": "VirusTotal detections for high severity",
        "default": 5,
        "type": "int",
    },
    "vt_severity_medium_threshold": {
        "category": "intel",
        "description": "VirusTotal detections for medium severity",
        "default": 2,
        "type": "int",
    },
    "vt_severity_low_threshold": {
        "category": "intel",
        "description": "VirusTotal detections for low severity",
        "default": 1,
        "type": "int",
    },
    "abuse_critical_threshold": {
        "category": "intel",
        "description": "AbuseIPDB score for critical severity",
        "default": 80,
        "type": "int",
    },
    "abuse_high_threshold": {
        "category": "intel",
        "description": "AbuseIPDB score for high severity",
        "default": 50,
        "type": "int",
    },
    "abuse_medium_threshold": {
        "category": "intel",
        "description": "AbuseIPDB score for medium severity",
        "default": 25,
        "type": "int",
    },
    "correlation_window_minutes": {
        "category": "correlation",
        "description": "Time window for event correlation in minutes",
        "default": 60,
        "type": "int",
    },
    "correlation_min_events": {
        "category": "correlation",
        "description": "Minimum events needed to trigger correlation pattern",
        "default": 2,
        "type": "int",
    },
    "bond_cisa_limit": {
        "category": "intel",
        "description": "Max CISA KEV entries per Bond scan",
        "default": 30,
        "type": "int",
    },
    "bond_nvd_limit": {
        "category": "intel",
        "description": "Max NVD entries per Bond scan",
        "default": 20,
        "type": "int",
    },
}


@router.get("/")
async def list_thresholds(
    category: str | None = Query(None),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all configurable thresholds with current values."""
    config = get_app_config()
    result = []
    for key, meta in THRESHOLD_REGISTRY.items():
        if category and meta["category"] != category:
            continue
        current_value = getattr(config, key, meta["default"])
        result.append({
            "key": key,
            "category": meta["category"],
            "description": meta["description"],
            "current_value": current_value,
            "default_value": meta["default"],
            "type": meta["type"],
        })
    return validate_and_log(result, ThresholdResponse, "GET /thresholds/")


@router.get("/{category}")
async def get_thresholds_by_category(
    category: str,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get thresholds filtered by category."""
    config = get_app_config()
    result = []
    for key, meta in THRESHOLD_REGISTRY.items():
        if meta["category"] != category:
            continue
        current_value = getattr(config, key, meta["default"])
        result.append({
            "key": key,
            "category": meta["category"],
            "description": meta["description"],
            "current_value": current_value,
            "default_value": meta["default"],
            "type": meta["type"],
        })
    if not result:
        raise HTTPException(status_code=404, detail=f"No thresholds found for category: {category}")
    return validate_and_log(result, ThresholdResponse, "GET /thresholds/{category}")


class ThresholdUpdate(BaseModel):
    value: int


@router.put("/{key}")
async def update_threshold(
    key: str,
    body: ThresholdUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Update a threshold at runtime. Persists to Settings DB table."""
    if key not in THRESHOLD_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Unknown threshold: {key}")

    # Update the config singleton
    config = get_app_config()
    if hasattr(config, key):
        object.__setattr__(config, key, body.value)

    # Also update RuleEngine class attribute if applicable
    if key == "exfil_bytes_threshold":
        try:
            from ...ai.rule_engine import RuleEngine
            RuleEngine.exfil_bytes_threshold = body.value
        except Exception:
            pass

    # Persist to Settings table
    from ...models.settings import Settings
    result = await db.execute(
        select(Settings).where(Settings.key == key, Settings.category == "threshold")
    )
    setting = result.scalar_one_or_none()
    if setting:
        setting.value = str(body.value)
    else:
        db.add(Settings(key=key, value=str(body.value), category="threshold"))
    await db.commit()

    meta = THRESHOLD_REGISTRY[key]
    return {
        "key": key,
        "value": body.value,
        "previous_default": meta["default"],
        "category": meta["category"],
    }
