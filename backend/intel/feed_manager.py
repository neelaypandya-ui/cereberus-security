"""Feed manager — orchestrates threat intelligence feed polling and IOC ingestion."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from ..models.ioc import IOC
from ..models.threat_feed import ThreatFeed
from ..utils.logging import get_logger
from .abuseipdb import AbuseIPDBProvider
from .urlhaus import URLhausProvider
from .virustotal import VirusTotalProvider

logger = get_logger("intel.feed_manager")


class FeedManager:
    """Manages threat intelligence feed polling and IOC ingestion.

    Loads enabled feeds from the database, launches per-feed asyncio polling
    tasks, deduplicates IOCs on ingestion, and tracks feed health.
    """

    def __init__(self, db_session_factory, config) -> None:
        self._session_factory = db_session_factory
        self._config = config
        self._polling_tasks: dict[int, asyncio.Task] = {}
        self._providers: dict[str, Any] = {}
        self._running = False

    async def start(self) -> None:
        """Load all enabled feeds from the database and start polling tasks."""
        self._running = True
        logger.info("feed_manager_starting")

        async with self._session_factory() as session:
            result = await session.execute(
                select(ThreatFeed).where(ThreatFeed.enabled == True)  # noqa: E712
            )
            feeds = result.scalars().all()

        for feed in feeds:
            self._launch_poll_task(feed.id, feed.poll_interval_seconds)

        logger.info("feed_manager_started", feed_count=len(feeds))

    def _launch_poll_task(self, feed_id: int, interval: int) -> None:
        """Launch an asyncio task that polls a feed at the configured interval."""
        if feed_id in self._polling_tasks:
            self._polling_tasks[feed_id].cancel()

        task = asyncio.create_task(self._poll_loop(feed_id, interval))
        self._polling_tasks[feed_id] = task
        logger.info("feed_poll_task_launched", feed_id=feed_id, interval=interval)

    async def _poll_loop(self, feed_id: int, interval: int) -> None:
        """Continuous polling loop for a single feed."""
        while self._running:
            try:
                await self._poll_feed(feed_id)
            except asyncio.CancelledError:
                logger.info("feed_poll_cancelled", feed_id=feed_id)
                return
            except Exception as exc:
                logger.error("feed_poll_error", feed_id=feed_id, error=str(exc))
            await asyncio.sleep(interval)

    async def _poll_feed(self, feed_id: int) -> None:
        """Poll a single feed: fetch config, dispatch to provider, ingest results."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(ThreatFeed).where(ThreatFeed.id == feed_id)
            )
            feed = result.scalar_one_or_none()
            if feed is None:
                logger.warning("feed_not_found", feed_id=feed_id)
                return

            if not feed.enabled:
                logger.info("feed_disabled_skipping", feed_id=feed_id, name=feed.name)
                return

            logger.info("feed_polling", feed_id=feed_id, name=feed.name, feed_type=feed.feed_type)

            # Parse optional config JSON
            feed_config = {}
            if feed.config_json:
                try:
                    feed_config = json.loads(feed.config_json)
                except json.JSONDecodeError:
                    pass

            # Decrypt API key if present
            api_key: Optional[str] = None
            if feed.api_key_encrypted:
                try:
                    from ..utils.encryption import decrypt_value
                    api_key = decrypt_value(feed.api_key_encrypted, self._config.secret_key)
                except Exception as exc:
                    logger.error("feed_api_key_decrypt_error", feed_id=feed_id, error=str(exc))

            # Dispatch to appropriate provider
            iocs: list[dict] = []
            try:
                iocs = await self._fetch_from_provider(feed.feed_type, api_key, feed_config)
            except Exception as exc:
                logger.error("feed_provider_error", feed_id=feed_id, error=str(exc))
                feed.last_polled = datetime.now(timezone.utc)
                await session.commit()
                return

            # Ingest IOCs
            ingested_count = await self._ingest_iocs(iocs, feed_id)

            # Update feed metadata
            now = datetime.now(timezone.utc)
            feed.last_polled = now
            feed.last_success = now
            feed.items_count = feed.items_count + ingested_count
            await session.commit()

            logger.info(
                "feed_poll_complete",
                feed_id=feed_id,
                name=feed.name,
                fetched=len(iocs),
                ingested=ingested_count,
            )

    async def _fetch_from_provider(
        self, feed_type: str, api_key: Optional[str], config: dict
    ) -> list[dict]:
        """Dispatch to the appropriate provider and return IOCs."""
        if feed_type == "virustotal":
            provider = VirusTotalProvider(api_key=api_key)
            # VirusTotal is lookup-based, not feed-based; use blacklist if configured
            targets = config.get("targets", [])
            iocs = []
            for target in targets:
                target_type = target.get("type", "hash")
                value = target.get("value", "")
                if target_type == "hash":
                    iocs.append(await provider.lookup_hash(value))
                elif target_type == "ip":
                    iocs.append(await provider.lookup_ip(value))
                elif target_type == "url":
                    iocs.append(await provider.lookup_url(value))
            return iocs

        elif feed_type == "abuseipdb":
            provider = AbuseIPDBProvider(api_key=api_key)
            limit = config.get("blacklist_limit", 100)
            return await provider.get_blacklist(limit=limit)

        elif feed_type == "urlhaus":
            provider = URLhausProvider()
            iocs = []
            url_limit = config.get("url_limit", 100)
            payload_limit = config.get("payload_limit", 50)
            urls = await provider.fetch_recent_urls(limit=url_limit)
            payloads = await provider.fetch_payloads(limit=payload_limit)
            iocs.extend(urls)
            iocs.extend(payloads)
            return iocs

        else:
            logger.warning("feed_unknown_type", feed_type=feed_type)
            return []

    async def _ingest_iocs(self, iocs: list[dict], feed_id: int) -> int:
        """Deduplicate and ingest IOCs into the database.

        Uses upsert pattern: insert new IOCs or update last_seen for existing ones.
        Deduplication key is (ioc_type, value).
        Returns the count of IOCs processed.
        """
        if not iocs:
            return 0

        count = 0
        async with self._session_factory() as session:
            for ioc_data in iocs:
                ioc_type = ioc_data.get("ioc_type", "")
                value = ioc_data.get("value", "")
                if not ioc_type or not value:
                    continue

                now = datetime.now(timezone.utc)
                context_json = json.dumps(ioc_data.get("context", {}))
                severity = ioc_data.get("severity", "medium")
                source = ioc_data.get("source", "")

                # Check if IOC already exists
                result = await session.execute(
                    select(IOC).where(IOC.ioc_type == ioc_type, IOC.value == value)
                )
                existing = result.scalar_one_or_none()

                if existing:
                    # Update last_seen and context
                    existing.last_seen = now
                    existing.context_json = context_json
                    existing.severity = severity
                    existing.active = True
                else:
                    # Insert new IOC
                    new_ioc = IOC(
                        ioc_type=ioc_type,
                        value=value,
                        source=source,
                        severity=severity,
                        last_seen=now,
                        context_json=context_json,
                        active=True,
                        feed_id=feed_id,
                    )
                    session.add(new_ioc)

                count += 1

            await session.commit()

        return count

    async def stop(self) -> None:
        """Cancel all polling tasks and shut down the feed manager."""
        self._running = False
        for feed_id, task in self._polling_tasks.items():
            task.cancel()
            logger.info("feed_poll_task_cancelled", feed_id=feed_id)
        self._polling_tasks.clear()
        logger.info("feed_manager_stopped")

    async def poll_feed_now(self, feed_id: int) -> None:
        """Trigger an immediate poll for a specific feed (on-demand)."""
        logger.info("feed_poll_immediate", feed_id=feed_id)
        await self._poll_feed(feed_id)
