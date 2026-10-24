from datetime import datetime, timezone
from investigation_store import connect
from ioc_classifier import classify_ioc
from risk_change import detect_risk_change
from risk_events import save_risk_event
from notifications import create_notification


def now():
    return datetime.now(timezone.utc).isoformat()


def initialize_monitor():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS monitored_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                ioc_type TEXT NOT NULL,
                interval_hours INTEGER NOT NULL DEFAULT 24,
                status TEXT NOT NULL DEFAULT 'active',
                last_checked TEXT,
                next_check TEXT,
                last_risk_score INTEGER,
                created_at TEXT NOT NULL
            )
        """)


def add_ioc(indicator, interval_hours=24):
    initialize_monitor()

    ioc = classify_ioc(indicator)

    if not ioc.get("valid"):
        return {
            "status": "rejected",
            "reason": ioc.get("error")
        }

    if not isinstance(interval_hours, int) or isinstance(interval_hours, bool) or interval_hours < 1:
        return {
            "status": "rejected",
            "reason": "Monitoring interval must be at least 1 hour"
        }

    with connect() as db:
        cursor = db.execute("""
            INSERT OR IGNORE INTO monitored_iocs (
                indicator, ioc_type, interval_hours,
                status, next_check, created_at
            )
            VALUES (?, ?, ?, 'active', ?, ?)
        """, (
            ioc["value"],
            ioc["type"],
            interval_hours,
            now(),
            now()
        ))

    return {
        "status": "added" if cursor.rowcount else "already_exists",
        "indicator": ioc["value"]
    }


def list_monitored():
    initialize_monitor()

    with connect() as db:
        rows = db.execute("""
            SELECT *
            FROM monitored_iocs
            ORDER BY id DESC
        """).fetchall()

    return [dict(row) for row in rows]


if __name__ == "__main__":
    initialize_monitor()
    print("PASS: IOC monitoring database initialized")
    print("Monitored IOCs:", len(list_monitored()))


def record_completed_investigation(indicator, report):
    """
    Update an IOC monitoring schedule after a completed investigation.
    Does not update monitoring records for failed investigations.
    """
    from datetime import timedelta

    if not isinstance(report, dict):
        return False

    if report.get("status") != "completed":
        return False

    assessment = report.get("risk_assessment") or {}
    risk_score = assessment.get("risk_score")

    if (
        not isinstance(risk_score, int)
        or isinstance(risk_score, bool)
        or not 0 <= risk_score <= 100
    ):
        risk_score = None

    initialize_monitor()

    with connect() as db:
        record = db.execute("""
            SELECT id, interval_hours, last_risk_score
            FROM monitored_iocs
            WHERE indicator = ?
              AND status = 'active'
        """, (indicator,)).fetchone()

        if record is None:
            return False

        checked_at = datetime.now(timezone.utc)
        next_check = checked_at + timedelta(
            hours=record["interval_hours"]
        )

        cursor = db.execute("""
            UPDATE monitored_iocs
            SET last_checked = ?,
                next_check = ?,
                last_risk_score = ?
            WHERE id = ?
              AND status = 'active'
        """, (
            checked_at.isoformat(),
            next_check.isoformat(),
            risk_score,
            record["id"]
        ))

        updated = cursor.rowcount == 1

        if updated and risk_score is not None:
            change = detect_risk_change(
                record["last_risk_score"],
                risk_score
            )

            if change["status"] != "invalid":
                save_risk_event(indicator, change, db=db)
                create_notification(indicator, change, db=db)

        return updated
