from datetime import datetime, timedelta, timezone

from investigation_store import connect
from job_queue import initialize_queue

MAX_ATTEMPTS = 3
RETRY_DELAYS = (60, 300)


def utc_now():
    return datetime.now(timezone.utc)


def initialize_retry_policy():
    initialize_queue()

    with connect() as db:
        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(investigation_jobs)"
            )
        }

        if "next_attempt_at" not in columns:
            db.execute("""
                ALTER TABLE investigation_jobs
                ADD COLUMN next_attempt_at TEXT
            """)


def schedule_retry(job_id, error, retryable=True, min_delay=0):
    initialize_retry_policy()

    with connect() as db:
        row = db.execute("""
            SELECT attempts, status
            FROM investigation_jobs
            WHERE id = ?
        """, (job_id,)).fetchone()

        if row is None or row["status"] != "running":
            return "not_running"

        attempts = row["attempts"]

        if not retryable or attempts >= MAX_ATTEMPTS:
            db.execute("""
                UPDATE investigation_jobs
                SET status = 'failed',
                    last_error = ?,
                    next_attempt_at = NULL,
                    updated_at = ?
                WHERE id = ?
            """, (
                str(error)[:500],
                utc_now().isoformat(),
                job_id
            ))

            return "failed"

        delay = RETRY_DELAYS[
            min(attempts - 1, len(RETRY_DELAYS) - 1)
        ]

        # Respect both the retry policy and provider cooldown.
        delay = max(delay, max(0, min(float(min_delay), 86400)))
        next_time = utc_now() + timedelta(seconds=delay)

        db.execute("""
            UPDATE investigation_jobs
            SET status = 'pending',
                last_error = ?,
                next_attempt_at = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            str(error)[:500],
            next_time.isoformat(),
            utc_now().isoformat(),
            job_id
        ))

        return "retry_scheduled"
