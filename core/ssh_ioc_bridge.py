import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ioc_classifier import classify_ioc
from job_queue import enqueue

BASE_DIR = Path(__file__).resolve().parent.parent
SSH_ALERTS = BASE_DIR / "detection" / "ssh_alerts.jsonl"
DATABASE = BASE_DIR / "data" / "ssh_bridge.db"


def initialize():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS ssh_ioc_alerts (
                alert_id TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                classification TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def main():
    initialize()

    print("[BRIDGE] SSH-to-IOC enrichment bridge")
    print("[BRIDGE] Persistent tracking enabled")
    print("[BRIDGE] External lookups disabled")

    if not SSH_ALERTS.exists():
        print("[BRIDGE] No SSH alerts found.")
        return

    new_alerts = 0
    duplicates = 0
    eligible = 0
    skipped = 0

    with sqlite3.connect(DATABASE) as db:
        with SSH_ALERTS.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                if not isinstance(alert, dict):
                    skipped += 1
                    continue

                source_ip = alert.get("source_ip")

                if not isinstance(source_ip, str):
                    skipped += 1
                    continue

                result = classify_ioc(source_ip)

                if not result.get("valid") or result.get("type") != "ip":
                    skipped += 1
                    continue

                alert_id = hashlib.sha256(
                    line.strip().encode("utf-8")
                ).hexdigest()

                is_public = result["classification"] == "public"

                status = "observed" if is_public else "skipped"

                cursor = db.execute("""
                    INSERT OR IGNORE INTO ssh_ioc_alerts (
                        alert_id,
                        source_ip,
                        classification,
                        status,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    result["value"],
                    result["classification"],
                    status,
                    datetime.now(timezone.utc).isoformat()
                ))

                if cursor.rowcount == 0:
                    duplicates += 1
                    continue

                new_alerts += 1

                if is_public:
                    eligible += 1
                    print("[NEW PUBLIC IOC]", result["value"])
                else:
                    skipped += 1
                    print("[SKIPPED]", result["value"])

        db.commit()

    print()
    print("[BRIDGE] New alerts:", new_alerts)
    print("[BRIDGE] Previously recorded:", duplicates)
    print("[BRIDGE] New public IOCs:", eligible)
    print("[BRIDGE] Skipped entries:", skipped)
    print("[BRIDGE] Tracking database:", DATABASE)
    print("[BRIDGE] No external investigations submitted.")


def submit_observed_iocs():
    """
    Explicitly authorized submission of previously observed public IPs.
    Does not perform external API lookups directly.
    """
    initialize()

    submitted = 0
    duplicates = 0
    rejected = 0

    with sqlite3.connect(DATABASE) as db:
        rows = db.execute("""
            SELECT alert_id, source_ip
            FROM ssh_ioc_alerts
            WHERE status = 'observed'
            ORDER BY created_at
        """).fetchall()

        for alert_id, source_ip in rows:
            result = classify_ioc(source_ip)

            if not (
                result.get("valid")
                and result.get("type") == "ip"
                and result.get("classification") == "public"
            ):
                db.execute("""
                    UPDATE ssh_ioc_alerts
                    SET status = 'skipped'
                    WHERE alert_id = ?
                """, (alert_id,))
                rejected += 1
                continue

            outcome = enqueue(source_ip, allow_external=True)

            if outcome["status"] in ("queued", "duplicate"):
                db.execute("""
                    UPDATE ssh_ioc_alerts
                    SET status = 'queued'
                    WHERE alert_id = ?
                """, (alert_id,))

                if outcome["status"] == "queued":
                    submitted += 1
                else:
                    duplicates += 1
            else:
                rejected += 1

        db.commit()

    print("[BRIDGE] New jobs queued:", submitted)
    print("[BRIDGE] Existing active jobs:", duplicates)
    print("[BRIDGE] Rejected:", rejected)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="SSH alert to IOC investigation bridge"
    )
    parser.add_argument(
        "--enable-enrichment",
        action="store_true",
        help="Authorize queue submission and external IOC enrichment"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously watch for new SSH alerts"
    )
    args = parser.parse_args()

    def run_cycle():
        main()

        if args.enable_enrichment:
            print("[BRIDGE] External enrichment explicitly enabled")
            submit_observed_iocs()
        else:
            print("[BRIDGE] Dry-run mode: queue submission disabled")

    if args.watch:
        import time

        print("[BRIDGE] Continuous monitoring started")
        print("[BRIDGE] Press Ctrl+C to stop")

        previous_state = None

        try:
            while True:
                try:
                    stat = SSH_ALERTS.stat()
                    current_state = (
                        stat.st_ino,
                        stat.st_size,
                        stat.st_mtime_ns
                    )
                except FileNotFoundError:
                    current_state = None

                if current_state != previous_state:
                    run_cycle()
                    previous_state = current_state

                time.sleep(5)

        except KeyboardInterrupt:
            print("\n[BRIDGE] Monitoring stopped")
    else:
        run_cycle()



