"""Abstract base class for all Cereberus security modules."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

from ..utils.logging import get_logger


class BaseModule(ABC):
    """Base class that all security modules must inherit from.

    Provides a standard lifecycle (start/stop) and health reporting interface.
    """

    def __init__(self, name: str, config: dict | None = None):
        self.name = name
        self.config = config or {}
        self.enabled = True
        self.running = False
        self.health_status = "initialized"
        self.last_heartbeat: Optional[datetime] = None
        self.logger = get_logger(f"module.{name}")

    @abstractmethod
    async def start(self) -> None:
        """Start the module's monitoring/processing loop."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the module."""
        ...

    @abstractmethod
    async def health_check(self) -> dict:
        """Return module health status.

        Returns:
            dict with keys: status (str), details (dict)
        """
        ...

    def heartbeat(self) -> None:
        """Update the last heartbeat timestamp."""
        self.last_heartbeat = datetime.now(timezone.utc)

    def get_status(self) -> dict:
        """Get current module status."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "running": self.running,
            "health_status": self.health_status,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
        }
