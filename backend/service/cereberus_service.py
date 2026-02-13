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

            # Determine paths — resolve from this file's location
            base_dir = Path(__file__).resolve().parent.parent.parent
            os.chdir(str(base_dir))

            # Find the real python.exe — sys.executable is pythonservice.exe
            # when running as a Windows Service. python.exe lives in the
            # same directory as pythonservice.exe.
            svc_dir = Path(sys.executable).parent
            candidate = svc_dir / "python.exe"
            python_exe = str(candidate) if candidate.exists() else sys.executable

            # Build env with correct paths — LocalSystem won't inherit
            # user PATH, so we need to set it explicitly.
            env = os.environ.copy()
            env["PATH"] = str(svc_dir) + os.pathsep + env.get("PATH", "")

            log_dir = base_dir / "logs"
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / "service_stdout.log"

            # Run uvicorn as subprocess, redirect output to log file
            with open(log_file, "a") as lf:
                self._server_process = subprocess.Popen(
                    [
                        python_exe, "-m", "uvicorn",
                        "backend.main:app",
                        "--host", "127.0.0.1",
                        "--port", "8000",
                        "--log-level", "info",
                    ],
                    cwd=str(base_dir),
                    env=env,
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                )

            # Wait for stop signal
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)


def is_service_available() -> bool:
    """Check if Windows Service functionality is available."""
    return _WIN32SERVICE


if __name__ == "__main__" and _WIN32SERVICE:
    win32serviceutil.HandleCommandLine(CereberusService)
