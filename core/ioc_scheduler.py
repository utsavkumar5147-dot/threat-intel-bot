import argparse
from datetime import datetime, timezone, timedelta

from investigation_store import connect
from ioc_classifier import classify_ioc
from ioc_monitor import initialize_monitor
from job_queue import enqueue


def due_iocs():
    initialize_monitor()

    current_time = datetime.now(timezone.utc).isoformat()

    with connect() as db:
        rows = db.execute("""
            SELECT *
            FROM monitored_iocs
            WHERE status = 'active'
              AND (
                  next_check IS NULL
                  OR next_check <= ?
              )
            ORDER BY next_check ASC, id ASC
        """, (current_time,)).fetchall()

    return [dict(row) for row in rows]


def run_scheduler(allow_external=False):
    records = due_iocs()

    print("[SCHEDULER] Due IOCs:", len(records))
    print(
        "[SCHEDULER] Mode:",
        "AUTHORIZED" if allow_external else "DRY RUN"
    )

    for record in records:
        indicator = record["indicator"]
        ioc = classify_ioc(indicator)

        if not ioc.get("valid"):
            print("[INVALID]", indicator)
            continue

        if ioc["type"] != "ip" or ioc["classification"] != "public":
            print("[NOT YET SUPPORTED FOR AUTOMATION]", indicator)
            continue

        if not allow_external:
            print("[WOULD QUEUE]", indicator)
            continue

        with connect() as db:
            active_job = db.execute("""
                SELECT id, status
                FROM investigation_jobs
                WHERE indicator = ?
                  AND status IN ('pending', 'running')
                LIMIT 1
            """, (indicator,)).fetchone()

        if active_job:
            print(
                "[ALREADY PROCESSING]",
                indicator,
                "Job:", active_job["id"]
            )
            continue

        # Prevent repeated new jobs after retry exhaustion.
        with connect() as db:
            failed_job = db.execute("""
                SELECT id, updated_at
                FROM investigation_jobs
                WHERE indicator = ?
                  AND status = 'failed'
                ORDER BY id DESC
                LIMIT 1
            """, (indicator,)).fetchone()

        if failed_job:
            try:
                failed_at = datetime.fromisoformat(
                    failed_job["updated_at"].replace("Z", "+00:00")
                ).astimezone(timezone.utc)
            except (ValueError, AttributeError):
                print("[INVALID FAILURE TIMESTAMP]", indicator)
                continue

            retry_after = failed_at + timedelta(hours=24)

            if datetime.now(timezone.utc) < retry_after:
                print(
                    "[FAILURE COOLDOWN]",
                    indicator,
                    "Retry after:",
                    retry_after.isoformat()
                )
                continue

        outcome = enqueue(indicator, allow_external=True)
        print("[QUEUE RESULT]", indicator, outcome["status"])

    print("[SCHEDULER] Cycle completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--enable-enrichment",
        action="store_true",
        help="Authorize external IOC enrichment through the queue"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously check for IOCs due for investigation"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Scheduler polling interval in seconds (minimum: 60)"
    )
    args = parser.parse_args()

    if args.interval < 60:
        parser.error("--interval must be at least 60 seconds")

    if args.watch:
        import time

        print("[SCHEDULER] Continuous monitoring started", flush=True)
        print("[SCHEDULER] Poll interval:", args.interval, "seconds", flush=True)
        print("[SCHEDULER] Press Ctrl+C to stop", flush=True)

        try:
            while True:
                try:
                    run_scheduler(
                        allow_external=args.enable_enrichment
                    )
                except Exception as error:
                    print("[SCHEDULER] Cycle error:", error, flush=True)

                time.sleep(args.interval)

        except KeyboardInterrupt:
            print("\n[SCHEDULER] Monitoring stopped")
    else:
        run_scheduler(allow_external=args.enable_enrichment)
