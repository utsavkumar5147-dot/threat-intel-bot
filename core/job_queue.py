import json
import sqlite3
from datetime import datetime, timezone

from investigation_store import connect
from ioc_classifier import classify_ioc


def now():
    return datetime.now(timezone.utc).isoformat()


def initialize_queue():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS investigation_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                allow_external INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                result_json TEXT
            )
        """)

        db.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_active_investigation_job
            ON investigation_jobs(indicator)
            WHERE status IN ('pending', 'running')
        """)


def enqueue(indicator, allow_external=False):
    initialize_queue()

    ioc = classify_ioc(indicator)

    if not ioc.get("valid"):
        return {
            "status": "rejected",
            "reason": ioc.get("error")
        }

    # Initial automation policy: public IP addresses only.
    if ioc["type"] != "ip" or ioc["classification"] != "public":
        return {
            "status": "rejected",
            "reason": "Background automation currently supports public IPs only"
        }

    if allow_external is not True:
        return {
            "status": "rejected",
            "reason": "Explicit external lookup permission required"
        }

    with connect() as db:
        try:
            cursor = db.execute("""
                INSERT INTO investigation_jobs (
                    indicator, ioc_type, status,
                    allow_external, created_at, updated_at
                )
                VALUES (?, ?, 'pending', 1, ?, ?)
            """, (
                ioc["value"],
                ioc["type"],
                now(),
                now()
            ))

            return {
                "status": "queued",
                "job_id": cursor.lastrowid,
                "indicator": ioc["value"]
            }

        except sqlite3.IntegrityError:
            row = db.execute("""
                SELECT id, status
                FROM investigation_jobs
                WHERE indicator = ?
                AND status IN ('pending', 'running')
            """, (ioc["value"],)).fetchone()

            if row is None:
                raise

            return {
                "status": "duplicate",
                "job_id": row["id"],
                "indicator": ioc["value"]
            }


def claim_next():
    initialize_queue()

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT *
            FROM investigation_jobs
            WHERE status = 'pending'
              AND attempts < 3
              AND (
                  next_attempt_at IS NULL
                  OR next_attempt_at <= ?
              )
            ORDER BY id ASC
            LIMIT 1
        """, (now(),)).fetchone()

        if row is None:
            return None

        db.execute("""
            UPDATE investigation_jobs
            SET status = 'running',
                attempts = attempts + 1,
                updated_at = ?
            WHERE id = ?
        """, (now(), row["id"]))

        return dict(row)


def finish_job(job_id, report):
    initialize_queue()

    if not isinstance(report, dict):
        raise ValueError("Expected investigation report")

    status = (
        "completed"
        if report.get("status") == "completed"
        else "failed"
    )

    with connect() as db:
        cursor = db.execute("""
            UPDATE investigation_jobs
            SET status = ?,
                result_json = ?,
                updated_at = ?,
                last_error = ?
            WHERE id = ? AND status = 'running'
        """, (
            status,
            json.dumps(report),
            now(),
            None if status == "completed"
            else str(report.get("message", "Investigation incomplete")),
            job_id
        ))

        return cursor.rowcount == 1


def recover_interrupted_jobs():
    initialize_queue()

    with connect() as db:
        cursor = db.execute("""
            UPDATE investigation_jobs
            SET status = 'pending',
                updated_at = ?
            WHERE status = 'running'
        """, (now(),))

        return cursor.rowcount


def queue_stats():
    initialize_queue()

    with connect() as db:
        rows = db.execute("""
            SELECT status, COUNT(*) AS count
            FROM investigation_jobs
            GROUP BY status
        """).fetchall()

    return {row["status"]: row["count"] for row in rows}


if __name__ == "__main__":
    initialize_queue()
    print("Queue initialized successfully.")
    print("Queue status:", queue_stats())


def save_partial_result(job_id, report):
    """Save an incomplete report without completing the job."""
    if not isinstance(report, dict):
        raise ValueError("Expected investigation report")

    with connect() as db:
        cursor = db.execute("""
            UPDATE investigation_jobs
            SET result_json = ?,
                updated_at = ?
            WHERE id = ?
              AND status = 'running'
        """, (
            json.dumps(report),
            now(),
            job_id
        ))

        return cursor.rowcount == 1


def get_partial_result(job_id):
    """Retrieve previously saved provider results."""
    with connect() as db:
        row = db.execute("""
            SELECT result_json
            FROM investigation_jobs
            WHERE id = ?
        """, (job_id,)).fetchone()

    if not row or not row["result_json"]:
        return None

    return json.loads(row["result_json"])



def complete_job_atomic(job_id, report):
    """Save investigation and finish job in one transaction."""
    import json
    from datetime import datetime, timezone
    from investigation_store import connect, initialize

    if not isinstance(report, dict):
        raise ValueError("Invalid investigation report")

    if report.get("status") != "completed":
        raise ValueError("Investigation is not completed")

    indicator = report.get("indicator")
    ioc_type = report.get("type")

    if not isinstance(indicator, str) or not indicator:
        raise ValueError("Missing indicator")

    if not isinstance(ioc_type, str) or not ioc_type:
        raise ValueError("Missing IOC type")

    assessment = report.get("risk_assessment") or {}

    if not isinstance(assessment, dict):
        raise ValueError("Invalid risk assessment")

    initialize()

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        job = db.execute(
            """
            SELECT status, indicator, ioc_type
            FROM investigation_jobs
            WHERE id = ?
            """,
            (job_id,)
        ).fetchone()

        if job is None or job["status"] != "running":
            raise ValueError("Job is not running")

        if (
            job["indicator"] != indicator
            or job["ioc_type"] != ioc_type
        ):
            raise ValueError("Report does not match queued job")

        timestamp = (
            report.get("investigated_at")
            or datetime.now(timezone.utc).isoformat()
        )

        history_id = None

        if report.get("cache_status") == "hit":
            candidate = report.get("database_id")

            if isinstance(candidate, int) and not isinstance(candidate, bool):
                existing = db.execute(
                    """
                    SELECT id, indicator, ioc_type, status
                    FROM investigations
                    WHERE id = ?
                    """,
                    (candidate,)
                ).fetchone()

                if (
                    existing is not None
                    and existing["indicator"] == indicator
                    and existing["ioc_type"] == ioc_type
                    and existing["status"] == "completed"
                ):
                    history_id = candidate

            if history_id is None:
                existing = db.execute(
                    """
                    SELECT id
                    FROM investigations
                    WHERE indicator = ?
                      AND ioc_type = ?
                      AND status = 'completed'
                      AND investigated_at = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (indicator, ioc_type, timestamp)
                ).fetchone()

                if existing is None:
                    raise ValueError("Cached history record not found")

                history_id = existing["id"]

        else:
            cursor = db.execute(
                """
                INSERT INTO investigations (
                    indicator, ioc_type, status,
                    risk_score, risk_level,
                    investigated_at, report_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    indicator,
                    ioc_type,
                    "completed",
                    assessment.get("risk_score"),
                    assessment.get("risk_level"),
                    timestamp,
                    json.dumps(report)
                )
            )

            history_id = cursor.lastrowid

        final_report = dict(report)
        final_report["database_id"] = history_id

        updated = db.execute(
            """
            UPDATE investigation_jobs
            SET status = 'completed',
                result_json = ?,
                updated_at = ?,
                last_error = NULL,
                next_attempt_at = NULL
            WHERE id = ? AND status = 'running'
            """,
            (
                json.dumps(final_report),
                datetime.now(timezone.utc).isoformat(),
                job_id
            )
        )

        if updated.rowcount != 1:
            raise RuntimeError("Job finalization failed")

        return history_id
