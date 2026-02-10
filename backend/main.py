"""Cereberus — AI-Powered Cybersecurity Defense System.

FastAPI entry point with lifespan management, module loading, and CORS.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sqlalchemy import select

from .api.router import api_router, websocket_router
from .api.websockets.events import manager as ws_manager
from .config import get_config
from .database import close_engine, create_tables, get_engine, get_session_factory
from .middleware.audit import AuditMiddleware
from .middleware.csrf import CSRFMiddleware
from .middleware.error_handler import register_error_handlers
from .middleware.request_id import RequestIDMiddleware
from .middleware.security_headers import ShieldWallMiddleware
from .middleware.rate_limit import GatekeeperMiddleware
from .dependencies import (
    get_alert_manager,
    get_anomaly_detector,
    get_behavioral_baseline,
    get_brute_force_shield,
    get_commander_bond,
    get_data_exporter,
    get_ensemble_detector,
    get_event_bus,
    get_event_log_monitor,
    get_feed_manager,
    get_file_integrity,
    get_incident_manager,
    get_ioc_matcher,
    get_memory_scanner,
    get_network_sentinel,
    get_notification_dispatcher,
    get_persistence_scanner,
    get_playbook_executor,
    get_process_analyzer,
    get_ransomware_detector,
    get_remediation_engine,
    get_resource_monitor,
    get_rule_engine,
    get_threat_intelligence,
    get_vpn_guardian,
    get_vuln_scanner,
    get_yara_scanner,
)
from .models.user import User
from .utils.cache import TTLCache
from .utils.logging import get_logger, setup_logging
from .utils.security import hash_password

config = get_config()
setup_logging(
    debug=config.debug,
    log_dir=config.log_dir,
    log_max_bytes=config.log_max_bytes,
    log_backup_count=config.log_backup_count,
)
logger = get_logger("cereberus.main")

# Task registry — name -> {task, factory, restarts, max_restarts}
_task_registry: dict[str, dict] = {}


def _register_task(name: str, coro_factory, max_restarts: int = 3):
    """Register and start a background task with auto-restart capability."""
    task = asyncio.create_task(coro_factory())
    _task_registry[name] = {
        "task": task,
        "factory": coro_factory,
        "restarts": 0,
        "max_restarts": max_restarts,
    }
    return task

# Health endpoint cache (15s TTL)
_health_cache = TTLCache(default_ttl=15.0, max_entries=5)

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


async def _seed_sword_policies(factory):
    """Seed Bond's default Sword Protocol policies (idempotent)."""
    try:
        from .models.sword_policy import SwordPolicy
        default_policies = [
            {
                "codename": "THUNDERBALL",
                "name": "Ransomware Kill Chain",
                "description": "Ransomware detected at critical level — kill, quarantine, isolate",
                "trigger_type": "module_event",
                "trigger_conditions": json.dumps({"source_module": "ransomware_detector", "event_type": "critical"}),
                "escalation_chain": json.dumps([
                    {"type": "kill_process", "target": "$details.pid"},
                    {"type": "quarantine_file", "target": "$details.path"},
                    {"type": "isolate_network", "target": "$details.interface"},
                ]),
                "cooldown_seconds": 60,
                "rate_limit": json.dumps({"max": 5, "window": 300}),
                "enabled": True,
                "requires_confirmation": False,
            },
            {
                "codename": "GOLDENEYE",
                "name": "C2 Beaconing Response",
                "description": "C2 beaconing detected — block IP and kill process",
                "trigger_type": "module_event",
                "trigger_conditions": json.dumps({"source_module": "network_sentinel", "event_type": "c2_beaconing"}),
                "escalation_chain": json.dumps([
                    {"type": "block_ip", "target": "$details.ip", "duration": 7200},
                    {"type": "kill_process", "target": "$details.pid"},
                ]),
                "cooldown_seconds": 120,
                "rate_limit": json.dumps({"max": 10, "window": 600}),
                "enabled": True,
                "requires_confirmation": False,
            },
            {
                "codename": "SKYFALL",
                "name": "Credential Dump Response",
                "description": "Credential dumping (T1003.*) detected — kill process",
                "trigger_type": "rule_match",
                "trigger_conditions": json.dumps({"rule_pattern": "T1003", "min_severity": "high"}),
                "escalation_chain": json.dumps([
                    {"type": "kill_process", "target": "$details.pid"},
                ]),
                "cooldown_seconds": 60,
                "rate_limit": json.dumps({"max": 10, "window": 300}),
                "enabled": True,
                "requires_confirmation": False,
            },
            {
                "codename": "SPECTRE",
                "name": "YARA Critical Match",
                "description": "Critical/high YARA match — quarantine file and kill process",
                "trigger_type": "yara_match",
                "trigger_conditions": json.dumps({"min_severity": "high"}),
                "escalation_chain": json.dumps([
                    {"type": "quarantine_file", "target": "$details.path"},
                    {"type": "kill_process", "target": "$details.pid"},
                ]),
                "cooldown_seconds": 120,
                "rate_limit": json.dumps({"max": 10, "window": 600}),
                "enabled": True,
                "requires_confirmation": False,
            },
            {
                "codename": "GHOST PROTOCOL",
                "name": "Memory Injection Response",
                "description": "Process injection detected in memory — kill process",
                "trigger_type": "memory_anomaly",
                "trigger_conditions": json.dumps({"finding_type": "rwx_region"}),
                "escalation_chain": json.dumps([
                    {"type": "kill_process", "target": "$details.pid"},
                ]),
                "cooldown_seconds": 60,
                "rate_limit": json.dumps({"max": 10, "window": 300}),
                "enabled": True,
                "requires_confirmation": False,
            },
        ]
        async with factory() as session:
            for pol_data in default_policies:
                result = await session.execute(
                    select(SwordPolicy).where(SwordPolicy.codename == pol_data["codename"])
                )
                if result.scalar_one_or_none() is None:
                    policy = SwordPolicy(
                        codename=pol_data["codename"],
                        name=pol_data["name"],
                        description=pol_data["description"],
                        trigger_type=pol_data["trigger_type"],
                        trigger_conditions_json=pol_data["trigger_conditions"],
                        escalation_chain_json=pol_data["escalation_chain"],
                        cooldown_seconds=pol_data["cooldown_seconds"],
                        rate_limit_json=pol_data.get("rate_limit"),
                        enabled=pol_data["enabled"],
                        requires_confirmation=pol_data["requires_confirmation"],
                    )
                    session.add(policy)
            await session.commit()
        logger.info("sword_policies_seeded")
    except Exception as e:
        logger.error("seed_sword_policies_failed", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    global _feed_manager_instance

    # --- Startup ---
    logger.info("cereberus_starting", host=config.host, port=config.port)

    # Secret key warning — The Default must not walk through the front door
    if config.secret_key == "CHANGE_ME_IN_PRODUCTION":
        if not config.debug:
            raise RuntimeError(
                "INSECURE_SECRET_KEY — default secret_key detected in production mode. "
                "Set a strong, unique SECRET_KEY in .env before deploying."
            )
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

    # Phase 12: Alert triage columns
    await _migrate_add_column("alerts", "dismissed", "BOOLEAN NOT NULL", "0")
    await _migrate_add_column("alerts", "dismissed_by", "VARCHAR(100)", "NULL")
    await _migrate_add_column("alerts", "dismissed_at", "DATETIME", "NULL")
    await _migrate_add_column("alerts", "snoozed_until", "DATETIME", "NULL")
    await _migrate_add_column("alerts", "escalated_to_incident_id", "INTEGER", "NULL")

    # Bond alert resolution
    await _migrate_add_column("alerts", "resolved_by", "VARCHAR(200)", "NULL")
    await _migrate_add_column("sword_execution_log", "resolved_alert_id", "INTEGER", "NULL")

    # Phase 13: IOC Lifecycle columns
    await _migrate_add_column("iocs", "confidence", "INTEGER", "NULL")
    await _migrate_add_column("iocs", "expires_at", "DATETIME", "NULL")
    await _migrate_add_column("iocs", "false_positive", "BOOLEAN NOT NULL", "0")
    await _migrate_add_column("iocs", "false_positive_reason", "VARCHAR(500)", "NULL")
    await _migrate_add_column("iocs", "false_positive_by", "VARCHAR(100)", "NULL")
    await _migrate_add_column("iocs", "false_positive_at", "DATETIME", "NULL")
    await _migrate_add_column("iocs", "hit_count", "INTEGER NOT NULL", "0")
    await _migrate_add_column("iocs", "last_hit_at", "DATETIME", "NULL")

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
        _register_task("vpn_guardian", lambda: vpn_guardian.start())
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
            _register_task("network_sentinel", lambda: network_sentinel.start())
            logger.info("network_sentinel_launched")
        except Exception as e:
            logger.error("network_sentinel_launch_failed", error=str(e))

    # Start Brute Force Shield
    brute_force_shield = None
    if config.module_brute_force_shield:
        brute_force_shield = get_brute_force_shield()
        try:
            _register_task("brute_force_shield", lambda: brute_force_shield.start())
            logger.info("brute_force_shield_launched")
        except Exception as e:
            logger.error("brute_force_shield_launch_failed", error=str(e))

    # Start File Integrity Monitor
    file_integrity = None
    if config.module_file_integrity:
        file_integrity = get_file_integrity()
        file_integrity.set_db_session_factory(factory)
        try:
            _register_task("file_integrity", lambda: file_integrity.start())
            logger.info("file_integrity_launched")
        except Exception as e:
            logger.error("file_integrity_launch_failed", error=str(e))

    # Start Process Analyzer
    process_analyzer = None
    if config.module_process_analyzer:
        process_analyzer = get_process_analyzer()
        process_analyzer.set_behavioral_baseline(behavioral_baseline)
        try:
            _register_task("process_analyzer", lambda: process_analyzer.start())
            logger.info("process_analyzer_launched")
        except Exception as e:
            logger.error("process_analyzer_launch_failed", error=str(e))

    # Start Vulnerability Scanner
    vuln_scanner = None
    if config.module_vuln_scanner:
        vuln_scanner = get_vuln_scanner()
        try:
            _register_task("vuln_scanner", lambda: vuln_scanner.start())
            logger.info("vuln_scanner_launched")
        except Exception as e:
            logger.error("vuln_scanner_launch_failed", error=str(e))

    # Start Resource Monitor
    resource_monitor = None
    if config.module_resource_monitor:
        resource_monitor = get_resource_monitor()
        resource_monitor.set_alert_manager(alert_manager)
        resource_monitor.set_behavioral_baseline(behavioral_baseline)
        try:
            _register_task("resource_monitor", lambda: resource_monitor.start())
            logger.info("resource_monitor_launched")
        except Exception as e:
            logger.error("resource_monitor_launch_failed", error=str(e))

    # Start Persistence Scanner
    persistence_scanner = None
    if config.module_persistence_scanner:
        persistence_scanner = get_persistence_scanner()
        try:
            _register_task("persistence_scanner", lambda: persistence_scanner.start())
            logger.info("persistence_scanner_launched")
        except Exception as e:
            logger.error("persistence_scanner_launch_failed", error=str(e))

    # Start Event Log Monitor (Phase 11) — EventBus wired in Phase 15
    event_log_monitor = None
    if config.module_event_log_monitor:
        event_log_monitor = get_event_log_monitor()
        try:
            _register_task("event_log_monitor", lambda: event_log_monitor.start())
            logger.info("event_log_monitor_launched")
        except Exception as e:
            logger.error("event_log_monitor_launch_failed", error=str(e))

    # Initialize Rule Engine (Phase 11)
    rule_engine = get_rule_engine()
    logger.info("rule_engine_initialized", rules=len(rule_engine.get_rules()))

    # Start Ransomware Detector (Phase 12)
    ransomware_detector = None
    if config.module_ransomware_detector:
        ransomware_detector = get_ransomware_detector()
        ransomware_detector.set_alert_manager(alert_manager)
        if process_analyzer:
            ransomware_detector.set_process_analyzer(process_analyzer)
        if file_integrity:
            ransomware_detector.set_file_integrity(file_integrity)
        try:
            _register_task("ransomware_detector", lambda: ransomware_detector.start())
            logger.info("ransomware_detector_launched")
        except Exception as e:
            logger.error("ransomware_detector_launch_failed", error=str(e))

    # --- Phase 15: Initialize EventBus + YARA + Memory Scanner ---

    # EventBus — Bond's ears
    event_bus = get_event_bus()
    await event_bus.start()
    logger.info("event_bus_started")

    # Wire EventBus to Event Log Monitor
    if event_log_monitor:
        event_log_monitor.set_event_bus(event_bus)
        logger.info("event_bus_wired_to_event_log_monitor")

    # YARA Scanner — Bond's Q-Branch arsenal
    yara_scanner = get_yara_scanner()
    try:
        yara_scanner.set_db_session_factory(factory)
        await yara_scanner.compile_rules()
        logger.info("yara_scanner_compiled", rules=len(yara_scanner.get_loaded_rules()))
    except Exception as e:
        logger.error("yara_scanner_compile_failed", error=str(e))

    # Wire YARA to File Integrity for auto-scan on changes
    if file_integrity and config.yara_auto_scan_on_integrity:
        file_integrity.set_yara_scanner(yara_scanner)
        logger.info("yara_wired_to_file_integrity")

    # Memory Scanner — Bond's reconnaissance
    memory_scanner = None
    if config.module_memory_scanner:
        memory_scanner = get_memory_scanner()
        memory_scanner.set_alert_manager(alert_manager)
        memory_scanner.set_yara_scanner(yara_scanner)
        memory_scanner.set_event_bus(event_bus)
        memory_scanner.set_db_session_factory(factory)
        try:
            _register_task("memory_scanner", lambda: memory_scanner.start())
            logger.info("memory_scanner_launched")
        except Exception as e:
            logger.error("memory_scanner_launch_failed", error=str(e))

    # Seed Sword Protocol default policies
    await _seed_sword_policies(factory)

    # Start Commander Bond (Phase 12) + Guardian wiring (Phase 14) + Phase 15 weapons
    commander_bond = None
    if config.module_commander_bond:
        commander_bond = get_commander_bond()
        commander_bond.set_alert_manager(alert_manager)
        # Phase 15: Wire Sword Protocol dependencies
        commander_bond.set_db_session_factory(factory)
        commander_bond.set_remediation_engine(remediation_engine)
        commander_bond.set_event_bus(event_bus)
        commander_bond.set_yara_scanner(yara_scanner)
        if memory_scanner:
            commander_bond.set_memory_scanner(memory_scanner)
        # Wire Bond into AlertManager for Sword evaluation
        alert_manager.set_commander_bond(commander_bond)
        logger.info("sword_protocol_wired")
        try:
            _register_task("commander_bond", lambda: commander_bond.start())
            logger.info("commander_bond_launched")
        except Exception as e:
            logger.error("commander_bond_launch_failed", error=str(e))

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
            _register_task("threat_intelligence", lambda: threat_intelligence.start())
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
                # Update baselines
                bl = get_behavioral_baseline()
                await bl.bulk_update_from_snapshots(history)
                logger.info("auto_retrain_baselines_complete")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("auto_retrain_error", error=str(e))

    _register_task("auto_retrain", _auto_retrain_loop)

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

    _register_task("retention_cleanup", _retention_cleanup_loop)

    # Health monitor loop — auto-restarts crashed tasks, broadcasts degradation warnings
    async def _health_monitor_loop():
        """Periodic health check of all modules and background tasks."""
        await asyncio.sleep(60)  # Initial delay
        while True:
            try:
                degraded = []
                for name, entry in list(_task_registry.items()):
                    if name == "health_monitor":
                        continue  # Don't monitor self
                    task = entry["task"]
                    if task.done() and not task.cancelled():
                        if entry["restarts"] < entry["max_restarts"]:
                            logger.warning("task_auto_restart", task=name, restart_count=entry["restarts"] + 1)
                            new_task = asyncio.create_task(entry["factory"]())
                            entry["task"] = new_task
                            entry["restarts"] += 1
                        else:
                            degraded.append(name)
                            logger.error("task_max_restarts_exceeded", task=name)

                if degraded:
                    try:
                        await ws_manager.broadcast({
                            "type": "health_warning",
                            "data": {"degraded_tasks": degraded},
                        })
                    except Exception as e:
                        logger.debug("health_warning_broadcast_failed", error=str(e))

                await asyncio.sleep(config.health_monitor_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("health_monitor_error", error=str(e))
                await asyncio.sleep(60)

    _register_task("health_monitor", _health_monitor_loop)

    logger.info("cereberus_started", app=config.app_name)

    yield

    # --- Shutdown ---
    logger.info("cereberus_shutting_down")

    # Broadcast shutdown notice
    try:
        await ws_manager.broadcast({"type": "server_shutdown", "data": {"message": "Server shutting down"}})
    except Exception as e:
        logger.debug("shutdown_broadcast_failed", error=str(e))

    # Stop verification loop
    remediation_engine.stop_verification_loop()

    # Stop feed manager
    if _feed_manager_instance:
        try:
            await asyncio.wait_for(_feed_manager_instance.stop(), timeout=5.0)
        except (asyncio.TimeoutError, Exception) as e:
            logger.error("feed_manager_stop_failed", error=str(e))

    # Stop EventBus
    try:
        await event_bus.stop()
    except Exception as e:
        logger.warning("event_bus_stop_failed", error=str(e))

    # Stop all modules with timeout
    for module, name in [
        (vpn_guardian, "vpn_guardian"),
        (network_sentinel, "network_sentinel"),
        (brute_force_shield, "brute_force_shield"),
        (file_integrity, "file_integrity"),
        (process_analyzer, "process_analyzer"),
        (vuln_scanner, "vuln_scanner"),
        (resource_monitor, "resource_monitor"),
        (persistence_scanner, "persistence_scanner"),
        (event_log_monitor, "event_log_monitor"),
        (ransomware_detector, "ransomware_detector"),
        (memory_scanner, "memory_scanner"),
        (commander_bond, "commander_bond"),
        (threat_intelligence, "threat_intelligence"),
    ]:
        if module is not None:
            try:
                await asyncio.wait_for(module.stop(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.error(f"{name}_stop_timeout")
            except Exception as e:
                logger.error(f"{name}_stop_failed", error=str(e))

    # Cancel all registered tasks
    for name, entry in _task_registry.items():
        task = entry["task"]
        if not task.done():
            task.cancel()

    # Give tasks a grace period to finish
    pending = [e["task"] for e in _task_registry.values() if not e["task"].done()]
    if pending:
        await asyncio.wait(pending, timeout=3.0)

    # Close all WebSocket connections
    try:
        await ws_manager.close_all()
    except Exception as e:
        logger.debug("ws_close_all_failed", error=str(e))

    # Close database
    await close_engine()
    logger.info("cereberus_stopped")


app = FastAPI(
    title="CEREBERUS",
    description="AI-Powered Cybersecurity Defense System",
    version="1.6.0",
    lifespan=lifespan,
)

# Register standard error handlers
register_error_handlers(app)

# CORS — origins from config (tightened: explicit methods + headers)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in config.cors_origins.split(",") if o.strip()],
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

# Request ID — correlation IDs on every request (added LAST so it runs FIRST)
app.add_middleware(RequestIDMiddleware)

# Mount API routes
app.include_router(api_router)
app.include_router(websocket_router)

# Serve frontend static files (SPA catch-all) — must be AFTER all API routes
_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    _assets_dir = _frontend_dist / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="static-assets")

    @app.get("/{full_path:path}")
    async def serve_spa(request: Request, full_path: str):
        """Serve frontend SPA — return index.html for non-API, non-asset paths."""
        # Skip API and WebSocket paths
        if full_path.startswith(("api/", "ws/", "health")):
            return {"detail": "Not found"}
        # Try to serve static file first
        file_path = _frontend_dist / full_path
        if full_path and file_path.is_file():
            return FileResponse(str(file_path))
        # Fall back to index.html for SPA routing
        index_path = _frontend_dist / "index.html"
        if index_path.is_file():
            return FileResponse(str(index_path))
        return {"name": config.app_name, "version": "1.6.0", "status": "operational"}
else:
    @app.get("/")
    async def root():
        """Root endpoint — health check (no frontend build available)."""
        return {
            "name": config.app_name,
            "version": "1.6.0",
            "status": "operational",
        }


@app.get("/health")
async def health():
    """Detailed health check."""

    async def _compute():
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

        if config.module_ransomware_detector:
            rd = get_ransomware_detector()
            modules["ransomware_detector"] = await rd.health_check()

        if config.module_memory_scanner:
            ms = get_memory_scanner()
            modules["memory_scanner"] = await ms.health_check()

        if config.module_commander_bond:
            bond = get_commander_bond()
            modules["commander_bond"] = await bond.health_check()

        return {
            "status": "healthy",
            "modules": modules,
        }

    return await _health_cache.get_or_compute("health", _compute, ttl=15.0)


def _ensure_port_available(host: str, port: int) -> None:
    """Kill any existing process holding our port before binding.

    Prevents [Errno 10048] on Windows when restarting the server.
    """
    import socket
    import subprocess
    import sys

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result != 0:
            return  # Port is free — nothing to do
    finally:
        sock.close()

    # Port is occupied — find and kill the holder
    logger.warning("port_occupied", host=host, port=port)
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["netstat", "-aon"],
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in out.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    parts = line.split()
                    pid = int(parts[-1])
                    if pid > 0:
                        logger.info("killing_stale_process", pid=pid, port=port)
                        subprocess.run(
                            ["taskkill", "/F", "/PID", str(pid)],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                        # Wait for port to release
                        import time
                        for _ in range(10):
                            time.sleep(0.5)
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                if s.connect_ex((host, port)) != 0:
                                    logger.info("port_released", port=port)
                                    return
                            finally:
                                s.close()
                    break
        except Exception as e:
            logger.warning("port_cleanup_failed", error=str(e))
    else:
        # Unix: use lsof
        try:
            out = subprocess.check_output(
                ["lsof", "-ti", f":{port}"],
                text=True,
            ).strip()
            if out:
                for pid_str in out.splitlines():
                    pid = int(pid_str)
                    logger.info("killing_stale_process", pid=pid, port=port)
                    import signal
                    os.kill(pid, signal.SIGTERM)
        except Exception as e:
            logger.warning("port_cleanup_failed", error=str(e))


def main():
    """Run the Cereberus server."""
    _ensure_port_available(config.host, config.port)
    uvicorn.run(
        "backend.main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level="debug" if config.debug else "info",
    )


if __name__ == "__main__":
    main()
