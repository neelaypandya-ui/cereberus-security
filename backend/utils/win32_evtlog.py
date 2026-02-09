"""Win32 EvtSubscribe wrappers — Bond's ears for real-time event subscription.

Uses ctypes to call Windows EvtSubscribe API for push-based event log
monitoring. Falls back gracefully on non-Windows systems.
"""

import asyncio
import ctypes
import ctypes.wintypes
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable, Optional

from .logging import get_logger

logger = get_logger("utils.win32_evtlog")

# Windows API constants
EVT_SUBSCRIBE_TO_FUTURE = 1
EVT_RENDER_EVENT_XML = 1
EvtRenderEventXml = 1

# Try to load Windows libraries
try:
    _wevtapi = ctypes.windll.wevtapi
    _kernel32 = ctypes.windll.kernel32
    _WINDOWS = True
except (AttributeError, OSError):
    _wevtapi = None
    _kernel32 = None
    _WINDOWS = False


def is_available() -> bool:
    """Check if EvtSubscribe API is available."""
    return _WINDOWS and _wevtapi is not None


class EvtSubscription:
    """Wraps a single EvtSubscribe channel subscription.

    Subscribes to a Windows Event Log channel with an XPath query.
    New events fire a callback with a parsed event dict.
    """

    def __init__(
        self,
        channel: str,
        query: str,
        callback: Callable[[dict], None],
    ):
        self._channel = channel
        self._query = query
        self._callback = callback
        self._handle = None
        self._signal_event = None
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._events_received: int = 0

    def start(self) -> bool:
        """Start the subscription. Returns True on success."""
        if not _WINDOWS:
            logger.warning("evt_subscribe_not_windows")
            return False

        try:
            # Create a Windows event for signaling
            self._signal_event = _kernel32.CreateEventW(None, False, False, None)
            if not self._signal_event:
                logger.error("evt_create_event_failed")
                return False

            # Subscribe to the channel
            channel_w = ctypes.c_wchar_p(self._channel)
            query_w = ctypes.c_wchar_p(self._query)

            self._handle = _wevtapi.EvtSubscribe(
                None,           # Session (None = local)
                self._signal_event,
                channel_w,
                query_w,
                None,           # Bookmark
                None,           # Context
                None,           # Callback (None = signal mode)
                EVT_SUBSCRIBE_TO_FUTURE,
            )

            if not self._handle:
                error = ctypes.get_last_error()
                logger.error("evt_subscribe_failed", channel=self._channel, error=error)
                return False

            self._running = True
            logger.info("evt_subscription_started", channel=self._channel)
            return True

        except Exception as e:
            logger.error("evt_subscribe_error", channel=self._channel, error=str(e))
            return False

    async def poll_loop(self) -> None:
        """Async loop that waits for signal events and reads them."""
        if not self._running or not self._handle:
            return

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                # Wait for signal in executor (non-blocking)
                signaled = await loop.run_in_executor(
                    None, self._wait_for_signal, 1000  # 1 second timeout
                )
                if signaled and self._running:
                    events = await loop.run_in_executor(None, self._read_events)
                    for event_dict in events:
                        try:
                            self._callback(event_dict)
                            self._events_received += 1
                        except Exception as e:
                            logger.error("evt_callback_error", error=str(e))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("evt_poll_error", channel=self._channel, error=str(e))
                await asyncio.sleep(1)

    def _wait_for_signal(self, timeout_ms: int) -> bool:
        """Wait for the signal event (blocking, runs in executor)."""
        if not self._signal_event:
            return False
        result = _kernel32.WaitForSingleObject(self._signal_event, timeout_ms)
        return result == 0  # WAIT_OBJECT_0

    def _read_events(self) -> list[dict]:
        """Read all pending events from the subscription."""
        events = []
        if not self._handle:
            return events

        while True:
            event_handle = ctypes.c_void_p()
            returned = ctypes.wintypes.DWORD()

            success = _wevtapi.EvtNext(
                self._handle,
                1,                          # Count
                ctypes.byref(event_handle),
                1000,                       # Timeout ms
                0,                          # Flags
                ctypes.byref(returned),
            )

            if not success or returned.value == 0:
                break

            # Render the event to XML
            xml_str = self._render_event_xml(event_handle.value)
            if xml_str:
                event_dict = self.parse_event_xml(xml_str)
                if event_dict:
                    events.append(event_dict)

            # Close event handle
            _wevtapi.EvtClose(event_handle)

        return events

    def _render_event_xml(self, event_handle) -> Optional[str]:
        """Render an event handle to XML string."""
        buffer_size = ctypes.wintypes.DWORD(0)
        buffer_used = ctypes.wintypes.DWORD(0)
        property_count = ctypes.wintypes.DWORD(0)

        # First call to get required buffer size
        _wevtapi.EvtRender(
            None,
            event_handle,
            EvtRenderEventXml,
            0,
            None,
            ctypes.byref(buffer_used),
            ctypes.byref(property_count),
        )

        if buffer_used.value == 0:
            return None

        # Allocate buffer and render
        buf = ctypes.create_unicode_buffer(buffer_used.value)
        success = _wevtapi.EvtRender(
            None,
            event_handle,
            EvtRenderEventXml,
            buffer_used.value * 2,  # Size in bytes (wide chars)
            buf,
            ctypes.byref(buffer_used),
            ctypes.byref(property_count),
        )

        if success:
            return buf.value
        return None

    @staticmethod
    def parse_event_xml(xml_str: str) -> Optional[dict]:
        """Parse Windows Event Log XML into a normalized dict."""
        try:
            # Remove namespace for easier parsing
            xml_clean = xml_str.replace('xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', '')
            root = ET.fromstring(xml_clean)

            system = root.find("System")
            if system is None:
                return None

            event_id_elem = system.find("EventID")
            event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

            provider_elem = system.find("Provider")
            provider = provider_elem.get("Name", "") if provider_elem is not None else ""

            time_elem = system.find("TimeCreated")
            timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""

            level_elem = system.find("Level")
            level = int(level_elem.text) if level_elem is not None and level_elem.text else 0

            computer_elem = system.find("Computer")
            computer = computer_elem.text if computer_elem is not None else ""

            channel_elem = system.find("Channel")
            channel = channel_elem.text if channel_elem is not None else ""

            # Parse EventData
            event_data = {}
            event_data_elem = root.find("EventData")
            if event_data_elem is not None:
                for data_elem in event_data_elem.findall("Data"):
                    name = data_elem.get("Name", "")
                    value = data_elem.text or ""
                    if name:
                        event_data[name] = value

            return {
                "event_id": event_id,
                "provider": provider,
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
                "level": level,
                "computer": computer,
                "channel": channel,
                "data": event_data,
                "raw_xml": xml_str[:5000],
            }
        except Exception as e:
            logger.debug("evt_xml_parse_error", error=str(e))
            return None

    def stop(self) -> None:
        """Stop the subscription and clean up handles."""
        self._running = False
        if self._handle:
            try:
                _wevtapi.EvtClose(self._handle)
            except Exception:
                pass
            self._handle = None
        if self._signal_event:
            try:
                _kernel32.CloseHandle(self._signal_event)
            except Exception:
                pass
            self._signal_event = None
        logger.info("evt_subscription_stopped", channel=self._channel, events=self._events_received)

    @property
    def events_received(self) -> int:
        return self._events_received
