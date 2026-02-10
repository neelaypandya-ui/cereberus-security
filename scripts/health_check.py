#!/usr/bin/env python3
"""Cereberus External Health Monitor.

Standalone script (stdlib only) that hits the /health endpoint and
reports status. Designed for Windows Task Scheduler or cron.

Exit codes:
    0 — healthy
    1 — unhealthy or unreachable

Usage:
    python scripts/health_check.py
    python scripts/health_check.py --url http://10.0.0.5:8000/health
    python scripts/health_check.py --webhook https://hooks.slack.com/...
"""

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_PATH = os.path.join(LOG_DIR, "health_check.log")

logger = logging.getLogger("cereberus.health_check")
logger.setLevel(logging.INFO)

_file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_file_handler)

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_console_handler)


# ---------------------------------------------------------------------------
# Health check logic
# ---------------------------------------------------------------------------

def check_health(url: str, timeout: int = 10) -> tuple[bool, dict]:
    """Hit the health endpoint and return (is_healthy, response_data)."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            is_healthy = data.get("status") == "healthy"
            return is_healthy, data
    except urllib.error.HTTPError as e:
        return False, {"error": f"HTTP {e.code}", "reason": str(e.reason)}
    except urllib.error.URLError as e:
        return False, {"error": "unreachable", "reason": str(e.reason)}
    except Exception as e:
        return False, {"error": "exception", "reason": str(e)}


def send_webhook(webhook_url: str, message: str) -> None:
    """Send a failure notification to a webhook URL (Slack-compatible JSON)."""
    payload = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            logger.info("Webhook notification sent")
    except Exception as e:
        logger.error("Webhook notification failed: %s", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Cereberus Health Monitor")
    parser.add_argument("--url", default="http://127.0.0.1:8000/health", help="Health endpoint URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--webhook", default=None, help="Webhook URL for failure notifications")
    args = parser.parse_args()

    now = datetime.now(timezone.utc).isoformat()
    is_healthy, data = check_health(args.url, timeout=args.timeout)

    if is_healthy:
        logger.info("HEALTHY — %s — %s", args.url, now)
        return 0
    else:
        msg = f"UNHEALTHY — {args.url} — {now} — {json.dumps(data)}"
        logger.error(msg)
        if args.webhook:
            send_webhook(args.webhook, f"Cereberus Health Alert: {msg}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
