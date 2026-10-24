from retry_policy import initialize_retry_policy, schedule_retry
from job_queue import recover_interrupted_jobs
from worker_lock import single_worker
import argparse
import json
import sys
import time
from datetime import datetime, timezone

from cached_intel import cached_investigate
from ioc_monitor import record_completed_investigation
from report_generator import generate_report
from unified_intel import investigate
from threat_scoring import calculate_risk
from investigation_store import save_investigation
from job_queue import save_partial_result, get_partial_result, complete_job_atomic, complete_job_atomic
from investigation_store import connect
from job_queue import claim_next, finish_job, queue_stats


def process_one():
    job = claim_next()

    if job is None:
        print("No pending investigations.")
        return False

    job_id = job["id"]
    indicator = job["indicator"]

    print(f"Processing job #{job_id}: {indicator}")

    try:
        if job["ioc_type"] != "ip" or job["allow_external"] != 1:
            raise ValueError("Job does not meet automation safety policy")

        previous = get_partial_result(job_id)

        if previous and previous.get("providers"):
            report = investigate(
                indicator,
                allow_external=True,
                previous_report=previous
            )
            report["risk_assessment"] = calculate_risk(report)
            report["cache_status"] = "partial_resume"
        else:
            report = cached_investigate(
                indicator,
                allow_external=True,
                save_history=False
            )

        if not isinstance(report, dict):
            raise ValueError("Invalid investigation response")

        if report.get("status") != "completed":
            providers = report.get("providers", {})

            statuses = [
                item.get("status")
                for item in providers.values()
                if isinstance(item, dict)
            ]

            permanent_error = any(
                "authentication" in str(item.get("message", "")).lower()
                or "access denied" in str(item.get("message", "")).lower()
                or "API_KEY is missing" in str(item.get("message", ""))
                for item in providers.values()
                if isinstance(item, dict)
            )

            cooldowns = []

            for item in providers.values():
                if not isinstance(item, dict):
                    continue

                if item.get("status") != "rate_limited":
                    continue

                result = item.get("result", item)

                if not isinstance(result, dict):
                    continue

                try:
                    cooldowns.append(
                        max(0, float(result.get("retry_after", 0)))
                    )
                except (TypeError, ValueError):
                    pass

            if not save_partial_result(job_id, report):
                raise RuntimeError("Could not save partial investigation")

            outcome = schedule_retry(
                job_id,
                "Incomplete investigation: " + ", ".join(statuses),
                retryable=not permanent_error,
                min_delay=max(cooldowns, default=0)
            )

            print("Investigation status:", report.get("status"))
            print("Retry outcome:", outcome)
            return True

        # Cached investigations may already exist in history.
        # Newly completed resumed investigations need atomic saving.
        report["database_id"] = complete_job_atomic(
            job_id, report
        )

        print("Investigation status:", report.get("status"))
        print("Cache status:", report.get("cache_status"))
        try:
            monitoring_updated = record_completed_investigation(
                indicator, report
            )
            if monitoring_updated:
                print("Monitoring schedule updated.")
        except Exception as monitoring_error:
            print(
                "Monitoring update failed:",
                monitoring_error
            )

        try:
            generated = generate_report(report)
            print("Investigation report:", generated["path"])
        except Exception as report_error:
            print("Report generation failed:", report_error)

        print("Job saved.")

    except Exception as exc:
        print("Investigation failed:", exc)

        outcome = schedule_retry(
            job_id,
            str(exc),
            retryable=True
        )
        print("Retry outcome:", outcome)

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one queued job"
    )
    args = parser.parse_args()

    initialize_retry_policy()
    print("Sentinel Background Worker")
    print("Queue:", queue_stats())

    if args.once:
        with single_worker():
            recovered = recover_interrupted_jobs()
            if recovered:
                print(f"Recovered {recovered} interrupted job(s).")
            process_one()
        return

    print("Starting continuous background processing...")
    print("Press Ctrl+C to stop safely.")

    try:
        with single_worker():
            recovered = recover_interrupted_jobs()

            if recovered:
                print(f"Recovered {recovered} interrupted job(s).")

            while True:
                processed = process_one()

                if not processed:
                    time.sleep(5)

    except KeyboardInterrupt:
        print("\\nShutdown requested. Worker stopped.")

    print("Sentinel worker exited.")


if __name__ == "__main__":
    main()
