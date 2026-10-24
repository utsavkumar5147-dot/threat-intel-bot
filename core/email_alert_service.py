import argparse
import json
import time
from pathlib import Path

from email_delivery_worker import process_one_email

CONFIG = Path.home() / ".config/threat-intel-bot/gmail-alerts.json"


def email_enabled():
    try:
        settings = json.loads(CONFIG.read_text(encoding="utf-8"))
        return settings.get("enabled") is True
    except (OSError, ValueError):
        return False


def check_alerts():
    if not email_enabled():
        return False

    try:
        return process_one_email()
    except Exception as error:
        print(
            "Email service error:",
            type(error).__name__,
            flush=True
        )
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()

    if args.interval < 5:
        parser.error("Interval must be at least 5 seconds")

    print("Sentinel Automatic Email Alert Service", flush=True)

    if args.once:
        check_alerts()
        print("PASS: Single email-service check completed")
        return

    print("Monitoring for HIGH-risk email alerts...", flush=True)
    print("Press Ctrl+C to stop.", flush=True)

    try:
        while True:
            check_alerts()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nEmail alert service stopped.")


if __name__ == "__main__":
    main()
