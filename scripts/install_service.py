"""Install/remove/configure Cereberus as a Windows Service.

Usage:
    python scripts/install_service.py install    - Install the service
    python scripts/install_service.py remove     - Remove the service
    python scripts/install_service.py start      - Start the service
    python scripts/install_service.py stop       - Stop the service
    python scripts/install_service.py restart    - Restart the service
    python scripts/install_service.py status     - Check service status
    python scripts/install_service.py recovery   - Configure crash recovery
"""

import subprocess
import sys


SERVICE_NAME = "CereberusDefense"
DISPLAY_NAME = "CEREBERUS Defense System"


def install_service():
    """Install the Windows Service."""
    try:
        from backend.service.cereberus_service import CereberusService
        import win32serviceutil
        win32serviceutil.InstallService(
            CereberusService._svc_reg_class_,
            SERVICE_NAME,
            DISPLAY_NAME,
            startType=2,  # SERVICE_AUTO_START
            description="AI-Powered Cybersecurity Defense System",
        )
        print(f"[+] Service '{SERVICE_NAME}' installed successfully.")
        configure_recovery()
    except ImportError:
        print("[-] pywin32 is required. Install with: pip install pywin32")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Installation failed: {e}")
        sys.exit(1)


def remove_service():
    """Remove the Windows Service."""
    try:
        import win32serviceutil
        win32serviceutil.RemoveService(SERVICE_NAME)
        print(f"[+] Service '{SERVICE_NAME}' removed successfully.")
    except Exception as e:
        print(f"[-] Removal failed: {e}")
        sys.exit(1)


def start_service():
    """Start the service."""
    try:
        import win32serviceutil
        win32serviceutil.StartService(SERVICE_NAME)
        print(f"[+] Service '{SERVICE_NAME}' started.")
    except Exception as e:
        print(f"[-] Start failed: {e}")
        sys.exit(1)


def stop_service():
    """Stop the service."""
    try:
        import win32serviceutil
        win32serviceutil.StopService(SERVICE_NAME)
        print(f"[+] Service '{SERVICE_NAME}' stopped.")
    except Exception as e:
        print(f"[-] Stop failed: {e}")
        sys.exit(1)


def restart_service():
    """Restart the service."""
    try:
        import win32serviceutil
        win32serviceutil.RestartService(SERVICE_NAME)
        print(f"[+] Service '{SERVICE_NAME}' restarted.")
    except Exception as e:
        print(f"[-] Restart failed: {e}")
        sys.exit(1)


def service_status():
    """Check service status."""
    try:
        import win32serviceutil
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        states = {
            1: "STOPPED",
            2: "START_PENDING",
            3: "STOP_PENDING",
            4: "RUNNING",
            5: "CONTINUE_PENDING",
            6: "PAUSE_PENDING",
            7: "PAUSED",
        }
        state_name = states.get(status[1], f"UNKNOWN ({status[1]})")
        print(f"[*] Service '{SERVICE_NAME}': {state_name}")
    except Exception as e:
        print(f"[-] Status check failed: {e}")
        sys.exit(1)


def configure_recovery():
    """Configure crash recovery: restart on failure (60s/300s/600s)."""
    cmd = [
        "sc", "failure", SERVICE_NAME,
        "reset=", "86400",
        "actions=", "restart/60000/restart/300000/restart/600000",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("[+] Recovery policy configured: restart at 60s/300s/600s")
    except subprocess.CalledProcessError as e:
        print(f"[-] Recovery config failed: {e.stderr}")
    except FileNotFoundError:
        print("[-] sc.exe not found — run as Administrator")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    action = sys.argv[1].lower()
    actions = {
        "install": install_service,
        "remove": remove_service,
        "start": start_service,
        "stop": stop_service,
        "restart": restart_service,
        "status": service_status,
        "recovery": configure_recovery,
    }

    if action not in actions:
        print(f"Unknown action: {action}")
        print(__doc__)
        sys.exit(1)

    actions[action]()


if __name__ == "__main__":
    main()
