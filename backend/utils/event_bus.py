"""EventBus — Bond's intelligence routing network.

Async pub/sub system that routes security events from all modules to
subscribers. Bond subscribes to everything for Sword Protocol evaluation.
"""

import asyncio
from collections import defaultdict
from typing import Callable, Coroutine, Any

from .logging import get_logger

logger = get_logger("utils.event_bus")


class EventBus:
    """Async publish/subscribe event bus for security events.

    Event types:
        security_event, sysmon_event, system_event, rule_match,
        yara_match, memory_anomaly, integrity_change, alert_created
    """

    def __init__(self, queue_size: int = 10000):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._wildcard_subscribers: list[Callable] = []
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._running: bool = False
        self._dispatch_task: asyncio.Task | None = None
        self._total_published: int = 0
        self._total_dispatched: int = 0
        self._total_dropped: int = 0

    def subscribe(self, event_type: str, handler: Callable[..., Coroutine[Any, Any, Any]]) -> None:
        """Subscribe to events of a specific type. Use '*' for all events."""
        if event_type == "*":
            if handler not in self._wildcard_subscribers:
                self._wildcard_subscribers.append(handler)
                logger.info("event_bus_wildcard_subscriber_added")
        else:
            if handler not in self._subscribers[event_type]:
                self._subscribers[event_type].append(handler)
                logger.info("event_bus_subscriber_added", event_type=event_type)

    def unsubscribe(self, event_type: str, handler: Callable) -> None:
        """Remove a subscription."""
        if event_type == "*":
            if handler in self._wildcard_subscribers:
                self._wildcard_subscribers.remove(handler)
        else:
            if handler in self._subscribers.get(event_type, []):
                self._subscribers[event_type].remove(handler)

    def publish(self, event_type: str, data: dict) -> None:
        """Publish an event (non-blocking). Drops if queue is full."""
        event = {"type": event_type, "data": data}
        try:
            self._queue.put_nowait(event)
            self._total_published += 1
        except asyncio.QueueFull:
            self._total_dropped += 1
            logger.warning("event_bus_queue_full", event_type=event_type)

    async def start(self) -> None:
        """Start the event dispatch loop."""
        self._running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())
        logger.info("event_bus_started")

    async def stop(self) -> None:
        """Stop the dispatch loop."""
        self._running = False
        if self._dispatch_task and not self._dispatch_task.done():
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
        logger.info("event_bus_stopped", published=self._total_published, dispatched=self._total_dispatched)

    async def _dispatch_loop(self) -> None:
        """Continuously drain the queue and dispatch to subscribers."""
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch_event(event)
                self._total_dispatched += 1
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("event_bus_dispatch_error", error=str(e))

    async def _dispatch_event(self, event: dict) -> None:
        """Dispatch a single event to all matching subscribers."""
        event_type = event.get("type", "unknown")
        data = event.get("data", {})

        handlers = list(self._subscribers.get(event_type, [])) + list(self._wildcard_subscribers)

        for handler in handlers:
            try:
                await asyncio.wait_for(handler(event_type, data), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("event_bus_handler_timeout", event_type=event_type)
            except Exception as e:
                logger.error("event_bus_handler_error", event_type=event_type, error=str(e))

    def get_stats(self) -> dict:
        """Return bus statistics."""
        return {
            "running": self._running,
            "total_published": self._total_published,
            "total_dispatched": self._total_dispatched,
            "total_dropped": self._total_dropped,
            "queue_size": self._queue.qsize(),
            "subscriber_count": sum(len(v) for v in self._subscribers.values()) + len(self._wildcard_subscribers),
            "event_types": list(self._subscribers.keys()),
        }
