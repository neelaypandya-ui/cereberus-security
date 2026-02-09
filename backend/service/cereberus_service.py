"""Cereberus Windows Service — Service Guardian.

Wraps the uvicorn server as a Windows Service for production deployment.
Service name: CereberusDefense, display: CEREBERUS Defense System.
Auto-start on boot with crash recovery (60s/300s/600s restart delays).

Optional deployment mode — dev still uses uvicorn directly.
"""

import os
import sys
from pathlib import Path

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    _WIN32SERVICE = True
except ImportError:
    _WIN32SERVICE = False


if _WIN32SERVICE:
    class CereberusService(win32serviceutil.ServiceFramework):
        """Windows Service wrapper for Cereberus."""

        _svc_name_ = "CereberusDefense"
        _svc_display_name_ = "CEREBERUS Defense System"
        _svc_description_ = "AI-Powered Cybersecurity Defense System — Autonomous Threat Detection and Response"

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._server_process = None

        def SvcStop(self):
            """Stop the service."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            if self._server_process:
                self._server_process.terminate()
                try:
                    self._server_process.wait(timeout=10)
                except Exception:
                    self._server_process.kill()

        def SvcDoRun(self):
            """Start the service — launch uvicorn."""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._run_server()

        def _run_server(self):
            """Run the Cereberus uvicorn server."""
            import subprocess

            # Determine paths
            base_dir = Path(__file__).resolve().parent.parent.parent
            os.chdir(str(base_dir))

            # Run uvicorn as subprocess
            self._server_process = subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn",
                    "backend.main:app",
                    "--host", "127.0.0.1",
                    "--port", "8000",
                    "--log-level", "info",
                ],
                cwd=str(base_dir),
            )

            # Wait for stop signal
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)


def is_service_available() -> bool:
    """Check if Windows Service functionality is available."""
    return _WIN32SERVICE
