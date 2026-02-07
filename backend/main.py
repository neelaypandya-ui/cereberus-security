"""Cereberus — AI-Powered Cybersecurity Defense System.

FastAPI entry point with lifespan management, module loading, and CORS.
"""

import asyncio
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import select

from .api.router import api_router, websocket_router
from .config import get_config
from .database import close_engine, create_tables, get_session_factory
from .middleware.audit import AuditMiddleware
from .dependencies import (
    get_alert_manager,
    get_anomaly_detector,
    get_behavioral_baseline,
    get_brute_force_shield,
    get_email_analyzer,
    get_ensemble_detector,
    get_file_integrity,
    get_isolation_forest_detector,
    get_network_sentinel,
    get_persistence_scanner,
    get_process_analyzer,
    get_resource_monitor,
    get_threat_forecaster,
    get_threat_intelligence,
    get_vpn_guardian,
    get_vuln_scanner,
    get_zscore_detector,
)
from .models.user import User
from .utils.logging import get_logger, setup_logging
from .utils.security import hash_password

config = get_config()
setup_logging(debug=config.debug)
logger = get_logger("cereberus.main")

# Track background module tasks
_module_tasks: list[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    # --- Startup ---
    logger.info("cereberus_starting", host=config.host, port=config.port)

    # Create database tables
    await create_tables(config)
    logger.info("database_initialized")

    # Seed default admin user if none exists
    factory = get_session_factory(config)
    async with factory() as session:
        result = await session.execute(select(User).limit(1))
        if result.scalar_one_or_none() is None:
            admin = User(
                username="admin",
                password_hash=hash_password("admin"),
                role="admin",
            )
            session.add(admin)
            await session.commit()
            logger.info("default_admin_created", username="admin")

    # Initialize alert manager
    get_alert_manager()

    # Start VPN Guardian module
    vpn_guardian = get_vpn_guardian()
    try:
        task = asyncio.create_task(vpn_guardian.start())
        _module_tasks.append(task)
        logger.info("vpn_guardian_launched")
    except Exception as e:
        logger.error("vpn_guardian_launch_failed", error=str(e))

    # Initialize behavioral baseline engine
    behavioral_baseline = get_behavioral_baseline()
    try:
        async with factory() as session:
            await behavioral_baseline.initialize(session)
        logger.info("behavioral_baseline_initialized")
    except Exception as e:
        logger.error("behavioral_baseline_init_failed", error=str(e))

    # Initialize threat forecaster
    threat_forecaster = get_threat_forecaster()
    try:
        await threat_forecaster.initialize()
        logger.info("threat_forecaster_initialized")
    except Exception as e:
        logger.error("threat_forecaster_init_failed", error=str(e))

    # Start Network Sentinel
    network_sentinel = None
    if config.module_network_sentinel:
        network_sentinel = get_network_sentinel()
        # Wire anomaly detector into network sentinel
        try:
            anomaly_detector = get_anomaly_detector()
            await anomaly_detector.initialize()
            network_sentinel.set_anomaly_detector(anomaly_detector)
            logger.info("anomaly_detector_wired_to_network_sentinel")
        except Exception as e:
            logger.error("anomaly_detector_init_failed", error=str(e))
        # Wire ensemble detector
        try:
            ifo = get_isolation_forest_detector()
            await ifo.initialize()
            zs = get_zscore_detector()
            await zs.initialize()
            ensemble = get_ensemble_detector()
            network_sentinel.set_ensemble_detector(ensemble)
            logger.info("ensemble_detector_wired_to_network_sentinel")
        except Exception as e:
            logger.error("ensemble_detector_init_failed", error=str(e))
        # Wire behavioral baseline and DB session factory
        network_sentinel.set_behavioral_baseline(behavioral_baseline)
        network_sentinel.set_db_session_factory(factory)
        try:
            task = asyncio.create_task(network_sentinel.start())
            _module_tasks.append(task)
            logger.info("network_sentinel_launched")
        except Exception as e:
            logger.error("network_sentinel_launch_failed", error=str(e))

    # Start Brute Force Shield
    brute_force_shield = None
    if config.module_brute_force_shield:
        brute_force_shield = get_brute_force_shield()
        try:
            task = asyncio.create_task(brute_force_shield.start())
            _module_tasks.append(task)
            logger.info("brute_force_shield_launched")
        except Exception as e:
            logger.error("brute_force_shield_launch_failed", error=str(e))

    # Start File Integrity Monitor
    file_integrity = None
    if config.module_file_integrity:
        file_integrity = get_file_integrity()
        try:
            task = asyncio.create_task(file_integrity.start())
            _module_tasks.append(task)
            logger.info("file_integrity_launched")
        except Exception as e:
            logger.error("file_integrity_launch_failed", error=str(e))

    # Start Process Analyzer
    process_analyzer = None
    if config.module_process_analyzer:
        process_analyzer = get_process_analyzer()
        try:
            task = asyncio.create_task(process_analyzer.start())
            _module_tasks.append(task)
            logger.info("process_analyzer_launched")
        except Exception as e:
            logger.error("process_analyzer_launch_failed", error=str(e))

    # Start Vulnerability Scanner
    vuln_scanner = None
    if config.module_vuln_scanner:
        vuln_scanner = get_vuln_scanner()
        try:
            task = asyncio.create_task(vuln_scanner.start())
            _module_tasks.append(task)
            logger.info("vuln_scanner_launched")
        except Exception as e:
            logger.error("vuln_scanner_launch_failed", error=str(e))

    # Start Email Analyzer
    email_analyzer = None
    if config.module_email_analyzer:
        email_analyzer = get_email_analyzer()
        try:
            task = asyncio.create_task(email_analyzer.start())
            _module_tasks.append(task)
            logger.info("email_analyzer_launched")
        except Exception as e:
            logger.error("email_analyzer_launch_failed", error=str(e))

    # Start Resource Monitor
    resource_monitor = None
    if config.module_resource_monitor:
        resource_monitor = get_resource_monitor()
        resource_monitor.set_alert_manager(get_alert_manager())
        resource_monitor.set_behavioral_baseline(behavioral_baseline)
        try:
            task = asyncio.create_task(resource_monitor.start())
            _module_tasks.append(task)
            logger.info("resource_monitor_launched")
        except Exception as e:
            logger.error("resource_monitor_launch_failed", error=str(e))

    # Start Persistence Scanner
    persistence_scanner = None
    if config.module_persistence_scanner:
        persistence_scanner = get_persistence_scanner()
        try:
            task = asyncio.create_task(persistence_scanner.start())
            _module_tasks.append(task)
            logger.info("persistence_scanner_launched")
        except Exception as e:
            logger.error("persistence_scanner_launch_failed", error=str(e))

    # Start Threat Intelligence (LAST — needs refs to other modules)
    threat_intelligence = None
    if config.module_threat_intelligence:
        threat_intelligence = get_threat_intelligence()
        # Provide references to other modules for event collection
        module_refs = {}
        if network_sentinel:
            module_refs["network_sentinel"] = network_sentinel
        if brute_force_shield:
            module_refs["brute_force_shield"] = brute_force_shield
        if file_integrity:
            module_refs["file_integrity"] = file_integrity
        if process_analyzer:
            module_refs["process_analyzer"] = process_analyzer
        if vuln_scanner:
            module_refs["vuln_scanner"] = vuln_scanner
        if resource_monitor:
            module_refs["resource_monitor"] = resource_monitor
        if persistence_scanner:
            module_refs["persistence_scanner"] = persistence_scanner
        threat_intelligence.set_module_refs(module_refs)

        try:
            task = asyncio.create_task(threat_intelligence.start())
            _module_tasks.append(task)
            logger.info("threat_intelligence_launched")
        except Exception as e:
            logger.error("threat_intelligence_launch_failed", error=str(e))

    # Start auto-retrain background loop
    async def _auto_retrain_loop():
        interval = config.ai_auto_retrain_interval_hours * 3600
        while True:
            try:
                await asyncio.sleep(interval)
                logger.info("auto_retrain_starting")
                # Retrain if resource monitor has sufficient data
                rm = get_resource_monitor()
                history = rm.get_history(limit=360)
                if len(history) >= 31:
                    fc = get_threat_forecaster()
                    if fc.initialized:
                        await fc.train(history, epochs=30)
                        await fc.save_model()
                        logger.info("auto_retrain_forecaster_complete")
                # Update baselines
                bl = get_behavioral_baseline()
                await bl.bulk_update_from_snapshots(history)
                logger.info("auto_retrain_baselines_complete")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("auto_retrain_error", error=str(e))

    retrain_task = asyncio.create_task(_auto_retrain_loop())
    _module_tasks.append(retrain_task)

    logger.info("cereberus_started", app=config.app_name)

    yield

    # --- Shutdown ---
    logger.info("cereberus_shutting_down")

    # Stop all modules
    for module, name in [
        (vpn_guardian, "vpn_guardian"),
        (network_sentinel, "network_sentinel"),
        (brute_force_shield, "brute_force_shield"),
        (file_integrity, "file_integrity"),
        (process_analyzer, "process_analyzer"),
        (vuln_scanner, "vuln_scanner"),
        (email_analyzer, "email_analyzer"),
        (resource_monitor, "resource_monitor"),
        (persistence_scanner, "persistence_scanner"),
        (threat_intelligence, "threat_intelligence"),
    ]:
        if module is not None:
            try:
                await module.stop()
            except Exception as e:
                logger.error(f"{name}_stop_failed", error=str(e))

    # Cancel background tasks
    for task in _module_tasks:
        task.cancel()

    # Close database
    await close_engine()
    logger.info("cereberus_stopped")


app = FastAPI(
    title="CEREBERUS",
    description="AI-Powered Cybersecurity Defense System",
    version="0.6.0",
    lifespan=lifespan,
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Audit middleware — logs mutating requests
app.add_middleware(AuditMiddleware, session_factory=None)  # session_factory set at startup

# Mount API routes
app.include_router(api_router)
app.include_router(websocket_router)


@app.get("/")
async def root():
    """Root endpoint — health check."""
    return {
        "name": config.app_name,
        "version": "0.6.0",
        "status": "operational",
    }


@app.get("/health")
async def health():
    """Detailed health check."""
    vpn = get_vpn_guardian()
    vpn_health = await vpn.health_check()

    modules = {"vpn_guardian": vpn_health}

    if config.module_network_sentinel:
        ns = get_network_sentinel()
        modules["network_sentinel"] = await ns.health_check()

    if config.module_brute_force_shield:
        bfs = get_brute_force_shield()
        modules["brute_force_shield"] = await bfs.health_check()

    if config.module_file_integrity:
        fi = get_file_integrity()
        modules["file_integrity"] = await fi.health_check()

    if config.module_process_analyzer:
        pa = get_process_analyzer()
        modules["process_analyzer"] = await pa.health_check()

    if config.module_vuln_scanner:
        vs = get_vuln_scanner()
        modules["vuln_scanner"] = await vs.health_check()

    if config.module_email_analyzer:
        ea = get_email_analyzer()
        modules["email_analyzer"] = await ea.health_check()

    if config.module_resource_monitor:
        rm = get_resource_monitor()
        modules["resource_monitor"] = await rm.health_check()

    if config.module_persistence_scanner:
        ps = get_persistence_scanner()
        modules["persistence_scanner"] = await ps.health_check()

    if config.module_threat_intelligence:
        ti = get_threat_intelligence()
        modules["threat_intelligence"] = await ti.health_check()

    return {
        "status": "healthy",
        "modules": modules,
    }


def main():
    """Run the Cereberus server."""
    uvicorn.run(
        "backend.main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level="debug" if config.debug else "info",
    )


if __name__ == "__main__":
    main()
