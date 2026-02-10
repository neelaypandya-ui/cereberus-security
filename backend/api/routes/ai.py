"""AI operations routes — training, status, models, predictions, feedback."""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, update, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_MANAGE_AI, PERM_VIEW_DASHBOARD
from ...dependencies import (
    get_anomaly_detector,
    get_behavioral_baseline,
    get_db,
    get_ensemble_detector,
    get_network_sentinel,
    get_resource_monitor,
)
from ...models.ai_model_registry import AIModelRegistry
from ...models.alert import Alert
from ...models.anomaly_event import AnomalyEvent

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/train/anomaly")
async def train_anomaly_models(
    epochs: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_AI)),
):
    """Train autoencoder anomaly detector on recent baseline data."""
    network_sentinel = get_network_sentinel()
    connections = network_sentinel.get_live_connections()

    if not connections:
        raise HTTPException(status_code=400, detail="No connection data available for training")

    # Build feature matrix from connection snapshots
    anomaly_detector = get_anomaly_detector()
    features = anomaly_detector.extract_features(connections)

    # Create synthetic training data by generating variations around current features
    import numpy as np
    rng = np.random.RandomState(42)
    n_samples = max(100, len(connections))
    base = features.reshape(1, -1).repeat(n_samples, axis=0)
    noise = rng.randn(n_samples, len(features)).astype(np.float32) * 0.1
    feature_matrix = base + noise * base

    results = {}

    # 1. Train autoencoder on real feature matrix
    try:
        ae_stats = await anomaly_detector.train_from_features(feature_matrix, epochs=epochs)
        await anomaly_detector.save_model()
        results["autoencoder"] = ae_stats

        # Register model
        version = await _get_next_version(db, "autoencoder")
        registry = AIModelRegistry(
            model_name="autoencoder",
            version=version,
            file_path=str(anomaly_detector.model_path),
            samples_count=n_samples,
            epochs=epochs,
            final_loss=ae_stats.get("final_loss", 0.0),
            metrics_json=json.dumps(ae_stats),
            status="active",
            is_current=True,
        )
        await _set_current_model(db, "autoencoder")
        db.add(registry)
        await db.commit()
    except Exception as e:
        results["autoencoder"] = {"error": str(e)}

    # Reset ensemble score history so drift measures post-training stability only
    ensemble = get_ensemble_detector()
    ensemble.reset_score_history()

    return {"status": "completed", "results": results}


@router.post("/train/baseline")
async def train_behavioral_baseline(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_AI)),
):
    """Build behavioral baselines from historical resource data."""
    resource_monitor = get_resource_monitor()
    history = resource_monitor.get_history(limit=360)

    baseline = get_behavioral_baseline()
    stats = await baseline.bulk_update_from_snapshots(history, db_session=db)

    return {"status": "completed", "results": stats}


@router.get("/models")
async def list_models(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all model versions from registry."""
    result = await db.execute(
        select(AIModelRegistry).order_by(desc(AIModelRegistry.created_at)).limit(100)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "model_name": r.model_name,
            "version": r.version,
            "trained_at": r.trained_at.isoformat(),
            "samples_count": r.samples_count,
            "epochs": r.epochs,
            "final_loss": r.final_loss,
            "status": r.status,
            "is_current": r.is_current,
        }
        for r in rows
    ]


@router.post("/models/{model_name}/rollback/{version}")
async def rollback_model(
    model_name: str,
    version: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_AI)),
):
    """Rollback a model to a previous version."""
    result = await db.execute(
        select(AIModelRegistry).where(
            AIModelRegistry.model_name == model_name,
            AIModelRegistry.version == version,
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"Model {model_name} version {version} not found")

    await _set_current_model(db, model_name)
    target.is_current = True
    target.status = "active"
    await db.commit()

    return {"status": "rolled_back", "model_name": model_name, "version": version}


@router.get("/status")
async def ai_status(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Comprehensive AI health status."""
    anomaly_detector = get_anomaly_detector()
    ensemble = get_ensemble_detector()
    baseline = get_behavioral_baseline()

    drift = ensemble.get_drift_score()
    last_ensemble = ensemble.get_last_result()

    return {
        "detectors": {
            "autoencoder": {
                "initialized": anomaly_detector.initialized,
                "threshold": anomaly_detector.threshold,
                "has_model": anomaly_detector.model is not None,
            },
        },
        "ensemble": {
            "last_score": last_ensemble.get("ensemble_score") if last_ensemble else None,
            "last_is_anomaly": last_ensemble.get("is_anomaly") if last_ensemble else None,
            "drift_score": drift,
        },
        "baseline": baseline.get_learning_progress(),
    }


@router.get("/anomaly-events")
async def get_anomaly_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    detector_type: str | None = None,
    is_anomaly_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Query persisted anomaly events."""
    query = select(AnomalyEvent).order_by(desc(AnomalyEvent.timestamp)).limit(limit).offset(offset)
    if detector_type:
        query = query.where(AnomalyEvent.detector_type == detector_type)
    if is_anomaly_only:
        query = query.where(AnomalyEvent.is_anomaly == True)

    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "detector_type": r.detector_type,
            "anomaly_score": r.anomaly_score,
            "threshold": r.threshold,
            "is_anomaly": r.is_anomaly,
            "explanation": r.explanation,
            "confidence": r.confidence,
            "detector_scores": json.loads(r.detector_scores_json) if r.detector_scores_json else {},
            "feature_attribution": json.loads(r.feature_attribution_json) if r.feature_attribution_json else {},
            "context": json.loads(r.context_json) if r.context_json else {},
        }
        for r in rows
    ]


@router.get("/baselines")
async def get_baselines(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """All behavioral baselines grouped by metric."""
    baseline = get_behavioral_baseline()
    all_baselines = baseline.get_all_baselines()

    grouped = {}
    for b in all_baselines:
        metric = b["metric_name"]
        if metric not in grouped:
            grouped[metric] = []
        grouped[metric].append(b)

    return {
        "baselines": grouped,
        "progress": baseline.get_learning_progress(),
    }


@router.get("/drift")
async def get_drift(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Model drift scores."""
    ensemble = get_ensemble_detector()
    return {
        "drift_score": ensemble.get_drift_score(),
        "last_result": ensemble.get_last_result(),
    }


@router.get("/feedback-stats")
async def get_feedback_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """TP/FP counts and accuracy by module."""
    result = await db.execute(
        select(
            Alert.module_source,
            Alert.feedback,
            func.count(Alert.id),
        )
        .where(Alert.feedback.isnot(None))
        .group_by(Alert.module_source, Alert.feedback)
    )
    rows = result.all()

    by_module = {}
    total_tp = 0
    total_fp = 0
    for module, feedback, count in rows:
        if module not in by_module:
            by_module[module] = {"true_positive": 0, "false_positive": 0}
        by_module[module][feedback] = count
        if feedback == "true_positive":
            total_tp += count
        elif feedback == "false_positive":
            total_fp += count

    total = total_tp + total_fp
    accuracy = total_tp / max(total, 1)

    return {
        "total_true_positive": total_tp,
        "total_false_positive": total_fp,
        "accuracy": round(accuracy, 3),
        "by_module": by_module,
    }


# --- Helper functions ---

async def _get_next_version(db: AsyncSession, model_name: str) -> int:
    """Get the next version number for a model."""
    result = await db.execute(
        select(func.max(AIModelRegistry.version)).where(
            AIModelRegistry.model_name == model_name
        )
    )
    current_max = result.scalar()
    return (current_max or 0) + 1


async def _set_current_model(db: AsyncSession, model_name: str) -> None:
    """Unset is_current for all versions of a model."""
    await db.execute(
        update(AIModelRegistry)
        .where(AIModelRegistry.model_name == model_name)
        .values(is_current=False)
    )
