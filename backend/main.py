"""Cereberus — AI-Powered Cybersecurity Defense System.

FastAPI entry point with lifespan management, module loading, and CORS.
"""

import asyncio
import json
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import select

from .api.router import api_router, websocket_router
from .api.websockets.events import manager as ws_manager
from .config import get_config
from .database import close_engine, create_tables, get_engine, get_session_factory
from .middleware.audit import AuditMiddleware
from .middleware.csrf import CSRFMiddleware
from .middleware.security_headers import ShieldWallMiddleware
from .middleware.rate_limit import GatekeeperMiddleware
from .dependencies import (
    get_alert_manager,
    get_anomaly_detector,
    get_behavioral_baseline,
    get_brute_force_shield,
    get_data_exporter,
    get_email_analyzer,
    get_ensemble_detector,
    get_event_log_monitor,
    get_feed_manager,
    get_file_integrity,
    get_incident_manager,
    get_ioc_matcher,
    get_isolation_forest_detector,
    get_network_sentinel,
    get_notification_dispatcher,
    get_persistence_scanner,
    get_playbook_executor,
    get_process_analyzer,
    get_remediation_engine,
    get_resource_monitor,
    get_rule_engine,
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

# Track services that need shutdown
_feed_manager_instance = None


async def _seed_default_roles(factory):
    """Seed RBAC default roles (idempotent)."""
    try:
        from .models.role import Role
        from .auth.rbac import DEFAULT_ROLES
        async with factory() as session:
            for role_name, role_def in DEFAULT_ROLES.items():
                result = await session.execute(
                    select(Role).where(Role.name == role_name)
                )
                if result.scalar_one_or_none() is None:
                    role = Role(
                        name=role_name,
                        description=role_def["description"],
                        permissions_json=json.dumps(role_def["permissions"]),
                    )
                    session.add(role)
            await session.commit()
        logger.info("default_roles_seeded")
    except Exception as e:
        logger.error("seed_roles_failed", error=str(e))


async def _assign_admin_role(factory):
    """Assign admin role to default admin user (idempotent)."""
    try:
        from .models.role import Role
        from .models.user_role import UserRole
        async with factory() as session:
            # Get admin user
            result = await session.execute(
                select(User).where(User.username == "admin")
            )
            admin_user = result.scalar_one_or_none()
            if not admin_user:
                return
            # Get admin role
            result = await session.execute(
                select(Role).where(Role.name == "admin")
            )
            admin_role = result.scalar_one_or_none()
            if not admin_role:
                return
            # Check if already assigned
            result = await session.execute(
                select(UserRole).where(
                    UserRole.user_id == admin_user.id,
                    UserRole.role_id == admin_role.id,
                )
            )
            if result.scalar_one_or_none() is None:
                session.add(UserRole(user_id=admin_user.id, role_id=admin_role.id))
                await session.commit()
                logger.info("admin_role_assigned")
    except Exception as e:
        logger.error("assign_admin_role_failed", error=str(e))


async def _seed_default_playbooks(factory):
    """Seed default playbook rules (idempotent by name)."""
    try:
        from .models.playbook_rule import PlaybookRule
        default_rules = [
            {
                "name": "Block Brute Force Attacker",
                "description": "Auto-block IP addresses that trigger brute force detection",
                "trigger_type": "module_event",
                "trigger_conditions": json.dumps({"source_module": "brute_force_shield", "event_type": "brute_force_detected"}),
                "actions": json.dumps([{"type": "block_ip", "target": "$details.ip", "duration": 3600}]),
                "cooldown_seconds": 60,
                "requires_confirmation": False,
                "enabled": True,
                "created_by": "system",
            },
            {
                "name": "Quarantine Suspicious Download",
                "description": "Quarantine files flagged by integrity monitor with high anomaly score",
                "trigger_type": "anomaly_score",
                "trigger_conditions": json.dumps({"min_score": 0.7, "source_module": "file_integrity"}),
                "actions": json.dumps([{"type": "quarantine_file", "target": "$details.path", "reason": "High anomaly score"}]),
                "cooldown_seconds": 300,
                "requires_confirmation": False,
                "enabled": True,
                "created_by": "system",
            },
            {
                "name": "Auto-Contain Critical Threat",
                "description": "Block IP and kill process on critical threat level",
                "trigger_type": "threat_level",
                "trigger_conditions": json.dumps({"level": "critical"}),
                "actions": json.dumps([
                    {"type": "block_ip", "target": "$details.ip", "duration": 7200},
                    {"type": "kill_process", "target": "$details.pid"},
                ]),
                "cooldown_seconds": 300,
                "requires_confirmation": False,
                "enabled": True,
                "created_by": "system",
            },
            {
                "name": "Network Isolation on Compromise",
                "description": "Isolate network adapter when potential compromise is correlated",
                "trigger_type": "correlation_pattern",
                "trigger_conditions": json.dumps({"pattern": "potential_compromise"}),
                "actions": json.dumps([{"type": "isolate_network", "target": "$details.interface"}]),
                "cooldown_seconds": 600,
                "requires_confirmation": True,
                "enabled": True,
                "created_by": "system",
            },
        ]
        async with factory() as session:
            for rule_data in default_rules:
                result = await session.execute(
                    select(PlaybookRule).where(PlaybookRule.name == rule_data["name"])
                )
                if result.scalar_one_or_none() is None:
                    rule = PlaybookRule(
                        name=rule_data["name"],
                        description=rule_data["description"],
                        trigger_type=rule_data["trigger_type"],
                        trigger_conditions_json=rule_data["trigger_conditions"],
                        actions_json=rule_data["actions"],
                        cooldown_seconds=rule_data["cooldown_seconds"],
                        requires_confirmation=rule_data["requires_confirmation"],
                        enabled=rule_data["enabled"],
                        created_by=rule_data["created_by"],
                    )
                    session.add(rule)
            await session.commit()
        logger.info("default_playbooks_seeded")
    except Exception as e:
        logger.error("seed_playbooks_failed", error=str(e))


async def _seed_default_feed(factory):
    """Seed a default URLhaus feed (disabled by default)."""
    try:
        from .models.threat_feed import ThreatFeed
        async with factory() as session:
            result = await session.execute(
                select(ThreatFeed).where(ThreatFeed.name == "URLhaus Recent URLs")
            )
            if result.scalar_one_or_none() is None:
                feed = ThreatFeed(
                    name="URLhaus Recent URLs",
                    feed_type="urlhaus",
                    url="https://urlhaus-api.abuse.ch/v1/urls/recent/",
                    enabled=False,
                    poll_interval_seconds=3600,
                )
                session.add(feed)
                await session.commit()
        logger.info("default_feed_seeded")
    except Exception as e:
        logger.error("seed_feed_failed", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    global _feed_manager_instance

    # --- Startup ---
    logger.info("cereberus_starting", host=config.host, port=config.port)

    # Secret key warning — The Default must not walk through the front door
    if config.secret_key == "CHANGE_ME_IN_PRODUCTION":
        logger.warning(
            "INSECURE_SECRET_KEY — default secret_key detected. "
            "Set a strong, unique SECRET_KEY in .env before deploying to production."
        )

    # Create database tables
    await create_tables(config)

    # Migrate existing tables — add columns that may not exist yet
    from sqlalchemy import text, inspect as sa_inspect
    engine = get_engine(config)

    async def _migrate_add_column(table: str, column: str, col_type: str, default: str | None = None):
        """Add a column to an existing table if it doesn't exist (no-op for new installs)."""
        try:
            async with engine.connect() as conn:
                result = await conn.execute(text(f"PRAGMA table_info({table})"))
                columns = [row[1] for row in result.fetchall()]
                if not columns:
                    return  # Table doesn't exist yet (new install — create_all handles it)
                if column not in columns:
                    default_clause = f" DEFAULT {default}" if default is not None else ""
                    await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause}"))
                    await conn.commit()
                    logger.info("migration_applied", table=table, column=column)
        except Exception as e:
            logger.warning("migration_skipped", table=table, column=column, error=str(e))

    await _migrate_add_column("users", "must_change_password", "BOOLEAN NOT NULL", "0")
    await _migrate_add_column("audit_logs", "semantic_event", "VARCHAR(100)", "NULL")
    # Phase 11: Remediation verification columns
    await _migrate_add_column("remediation_actions", "verification_status", "VARCHAR(20)", "NULL")
    await _migrate_add_column("remediation_actions", "verification_result_json", "TEXT", "NULL")
    await _migrate_add_column("remediation_actions", "verified_at", "DATETIME", "NULL")
    await _migrate_add_column("remediation_actions", "verification_attempts", "INTEGER", "0")

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
                must_change_password=True,
            )
            session.add(admin)
            await session.commit()
            logger.info("default_admin_created", username="admin")

    # Seed RBAC roles and assign admin role
    await _seed_default_roles(factory)
    await _assign_admin_role(factory)

    # Seed default playbook rules
    await _seed_default_playbooks(factory)

    # Seed default threat feed
    await _seed_default_feed(factory)

    # Initialize alert manager and wire DB session factory
    alert_manager = get_alert_manager()
    alert_manager.set_db_session_factory(factory)

    # --- Phase 7: Initialize engine singletons ---
    remediation_engine = get_remediation_engine()
    remediation_engine.set_db_session_factory(factory)
    remediation_engine.set_ws_broadcast(ws_manager.broadcast)
    remediation_engine.start_verification_loop()
    logger.info("remediation_engine_initialized")

    incident_manager = get_incident_manager()
    incident_manager.set_db_session_factory(factory)
    incident_manager.set_ws_broadcast(ws_manager.broadcast)
    logger.info("incident_manager_initialized")

    playbook_executor = get_playbook_executor()
    playbook_executor.set_db_session_factory(factory)
    playbook_executor.set_remediation_engine(remediation_engine)
    playbook_executor.set_ws_broadcast(ws_manager.broadcast)
    logger.info("playbook_executor_initialized")

    # Wire playbook executor and notification dispatcher into alert manager
    alert_manager.set_playbook_executor(playbook_executor)

    # --- Phase 8: Initialize integration singletons ---
    ioc_matcher = get_ioc_matcher()
    notification_dispatcher = get_notification_dispatcher()
    alert_manager.set_notification_dispatcher(notification_dispatcher)
    logger.info("notification_dispatcher_wired")

    # Initialize data exporter
    get_data_exporter()
    logger.info("data_exporter_initialized")

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
        # Wire IOC matcher (Phase 8)
        network_sentinel.set_ioc_matcher(ioc_matcher)
        try:
            task = asyncio.create_task(network_sentinel.start())
            _module_tasks.append(task)
            logger.info("network_sentinel_launched")
        except Exception as e:
            logger.error("network_sentinel_launch_failed", error=str(e))

        # Delayed real-data AI auto-training
        async def _delayed_real_data_train():
            """Wait 5 min, collect 10 real snapshots, train on real data."""
            try:
                await asyncio.sleep(300)  # Wait 5 minutes for real data
                logger.info("real_data_ai_training_starting")

                ns = get_network_sentinel()
                ad = get_anomaly_detector()
                if not (ad.initialized and hasattr(ad, 'extract_features')):
                    return

                import numpy as np
                samples = []
                for i in range(10):
                    conns = ns.get_live_connections()
                    if conns:
                        features = ad.extract_features(conns)
                        samples.append(features)
                    if i < 9:
                        await asyncio.sleep(30)

                if len(samples) < 5:
                    logger.warning("real_data_train_insufficient_samples", count=len(samples))
                    return

                real_data = np.vstack([s.reshape(1, -1) for s in samples])
                # Augment with small noise
                noise = np.random.normal(0, 0.03, (20, real_data.shape[1]))
                mean_sample = real_data.mean(axis=0)
                augmented = mean_sample + noise
                train_data = np.vstack([real_data, augmented])

                ifo = get_isolation_forest_detector()
                if ifo._model is None:
                    ifo.train(train_data)
                    await ifo.save_model()
                    logger.info("isolation_forest_real_data_trained", samples=len(train_data))

                zs = get_zscore_detector()
                if zs._mean is None:
                    zs.update_baseline(train_data)
                    await zs.save_baseline()
                    logger.info("zscore_real_data_trained", samples=len(train_data))
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.error("real_data_train_failed", error=str(e))

        if network_sentinel:
            train_task = asyncio.create_task(_delayed_real_data_train())
            _module_tasks.append(train_task)

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
        file_integrity.set_db_session_factory(factory)
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
        resource_monitor.set_alert_manager(alert_manager)
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

    # Start Event Log Monitor (Phase 11)
    event_log_monitor = None
    if config.module_event_log_monitor:
        event_log_monitor = get_event_log_monitor()
        try:
            task = asyncio.create_task(event_log_monitor.start())
            _module_tasks.append(task)
            logger.info("event_log_monitor_launched")
        except Exception as e:
            logger.error("event_log_monitor_launch_failed", error=str(e))

    # Initialize Rule Engine (Phase 11)
    rule_engine = get_rule_engine()
    logger.info("rule_engine_initialized", rules=len(rule_engine.get_rules()))

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
        if event_log_monitor:
            module_refs["event_log_monitor"] = event_log_monitor
        threat_intelligence.set_module_refs(module_refs)
        threat_intelligence.set_rule_engine(rule_engine)

        # Wire Phase 7 engines + alert manager
        threat_intelligence.set_playbook_executor(playbook_executor)
        threat_intelligence.set_incident_manager(incident_manager)
        threat_intelligence.set_alert_manager(alert_manager)

        try:
            task = asyncio.create_task(threat_intelligence.start())
            _module_tasks.append(task)
            logger.info("threat_intelligence_launched")
        except Exception as e:
            logger.error("threat_intelligence_launch_failed", error=str(e))

    # Start Feed Manager (Phase 8)
    if config.feed_poll_enabled:
        try:
            fm = get_feed_manager()
            await fm.start()
            _feed_manager_instance = fm
            logger.info("feed_manager_started")
        except Exception as e:
            logger.error("feed_manager_start_failed", error=str(e))

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

    # Start retention cleanup loop (Phase 9)
    async def _retention_cleanup_loop():
        interval = config.retention_cleanup_interval_hours * 3600
        while True:
            try:
                await asyncio.sleep(interval)
                logger.info("retention_cleanup_starting")
                from .maintenance.retention import RetentionManager
                rm = RetentionManager(db_session_factory=factory, config=config)
                summary = await rm.run_cleanup()
                logger.info("retention_cleanup_complete", summary=summary)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("retention_cleanup_error", error=str(e))

    retention_task = asyncio.create_task(_retention_cleanup_loop())
    _module_tasks.append(retention_task)

    # Chunk 11: Threat Forecaster broadcast loop — The Oracle speaks
    async def _forecast_check_loop():
        """Run threat forecaster every 5 min, broadcast predictions, create alerts."""
        await asyncio.sleep(600)  # Wait 10 min for sufficient data
        while True:
            try:
                rm = get_resource_monitor()
                fc = get_threat_forecaster()
                if not fc.initialized:
                    await asyncio.sleep(300)
                    continue

                history = rm.get_history(limit=360)
                if len(history) < 30:
                    await asyncio.sleep(300)
                    continue

                predictions = await fc.predict_trend(history, steps=6)
                if predictions:
                    # Broadcast prediction_update via WebSocket
                    await ws_manager.broadcast({
                        "type": "prediction_update",
                        "data": predictions,
                    })

                    # Check for threshold breaches
                    forecast_alerts = fc.check_forecast_alerts(predictions)
                    for fa in forecast_alerts:
                        await alert_manager.create_alert(
                            severity="medium",
                            module="threat_forecaster",
                            title=f"Predicted {fa['metric']} breach in {fa['minutes_until_breach']}min",
                            details=json.dumps(fa),
                        )
                await asyncio.sleep(300)  # 5-minute interval
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("forecast_check_error", error=str(e))
                await asyncio.sleep(300)

    forecast_task = asyncio.create_task(_forecast_check_loop())
    _module_tasks.append(forecast_task)

    logger.info("cereberus_started", app=config.app_name)

    yield

    # --- Shutdown ---
    logger.info("cereberus_shutting_down")

    # Stop verification loop
    remediation_engine.stop_verification_loop()

    # Stop feed manager
    if _feed_manager_instance:
        try:
            await _feed_manager_instance.stop()
        except Exception as e:
            logger.error("feed_manager_stop_failed", error=str(e))

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
        (event_log_monitor, "event_log_monitor"),
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
    version="1.1.0",
    lifespan=lifespan,
)

# CORS — allow frontend dev server (tightened: explicit methods + headers)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-CSRF-Token"],
)

# CSRF protection — validates X-CSRF-Token on state-changing requests
app.add_middleware(CSRFMiddleware)

# The Shield Wall — security headers on every response
app.add_middleware(ShieldWallMiddleware)

# The Gatekeeper — rate limiting on state-changing endpoints
app.add_middleware(GatekeeperMiddleware)

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
        "version": "1.0.0",
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

    if config.module_event_log_monitor:
        elm = get_event_log_monitor()
        modules["event_log_monitor"] = await elm.health_check()

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
