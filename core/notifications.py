from datetime import datetime, timezone

from investigation_store import connect


def initialize_notifications():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unread',
                created_at TEXT NOT NULL
            )
        """)


def create_notification(indicator, change, db=None):
    if not isinstance(change, dict):
        return None

    if not change.get("significant"):
        return None

    status = change.get("status")

    if status not in ("increased", "decreased"):
        return None

    previous = change.get("previous_score")
    current = change.get("current_score")

    if status == "increased":
        title = "IOC Risk Increased"
        severity = "HIGH"
    else:
        title = "IOC Risk Decreased"
        severity = "INFO"

    message = (
        f"Risk score for {indicator} changed "
        f"from {previous} to {current}."
    )

    if db is None:
        initialize_notifications()
        with connect() as connection:
            return create_notification(
                indicator, change, db=connection
            )

    db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unread',
            created_at TEXT NOT NULL
        )
    """)

    cursor = db.execute("""
        INSERT INTO notifications (
            indicator, title, message,
            severity, created_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        indicator,
        title,
        message,
        severity,
        datetime.now(timezone.utc).isoformat()
    ))

    return cursor.lastrowid


def list_notifications(limit=50):
    initialize_notifications()

    with connect() as db:
        rows = db.execute("""
            SELECT *
            FROM notifications
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


if __name__ == "__main__":
    initialize_notifications()
    print("PASS: Notification database initialized")
    print("Notifications:", len(list_notifications()))
