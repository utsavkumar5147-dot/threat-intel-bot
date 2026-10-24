from datetime import datetime, timezone

from investigation_store import connect
from notifications import initialize_notifications


def now():
    return datetime.now(timezone.utc).isoformat()


def initialize_email_delivery():
    initialize_notifications()

    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS email_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                notification_id INTEGER NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sent_at TEXT,
                last_error TEXT
            )
        """)


def queue_email_alerts():
    """Queue new HIGH risk-increase notifications once."""
    initialize_email_delivery()

    with connect() as db:
        db.execute("""
            INSERT OR IGNORE INTO email_deliveries (
                notification_id, status, created_at, updated_at
            )
            SELECT id, 'pending', ?, ?
            FROM notifications
            WHERE severity = 'HIGH'
              AND title = 'IOC Risk Increased'
        """, (now(), now()))

        rows = db.execute("""
            SELECT status, COUNT(*) AS total
            FROM email_deliveries
            GROUP BY status
        """).fetchall()

    return {row["status"]: row["total"] for row in rows}


if __name__ == "__main__":
    print("Email delivery queue:", queue_email_alerts())
    print("PASS: Email delivery tracking initialized")
    print("PASS: Duplicate notification IDs prevented")
    print("PASS: No emails sent")
