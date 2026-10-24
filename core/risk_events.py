import json
from datetime import datetime, timezone

from investigation_store import connect


def initialize_risk_events():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS risk_change_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                previous_score INTEGER,
                current_score INTEGER NOT NULL,
                change_amount INTEGER,
                change_status TEXT NOT NULL,
                significant INTEGER NOT NULL DEFAULT 0,
                detected_at TEXT NOT NULL
            )
        """)


def save_risk_event(indicator, change, db=None):
    if not isinstance(change, dict):
        raise ValueError("Risk change must be a dictionary")

    if change.get("status") not in (
        "baseline", "increased", "decreased", "stable"
    ):
        raise ValueError("Unsupported risk change status")

    if db is None:
        initialize_risk_events()
        with connect() as connection:
            return save_risk_event(
                indicator, change, db=connection
            )

    db.execute("""
        CREATE TABLE IF NOT EXISTS risk_change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            previous_score INTEGER,
            current_score INTEGER NOT NULL,
            change_amount INTEGER,
            change_status TEXT NOT NULL,
            significant INTEGER NOT NULL DEFAULT 0,
            detected_at TEXT NOT NULL
        )
    """)

    cursor = db.execute("""
        INSERT INTO risk_change_events (
            indicator, previous_score, current_score,
            change_amount, change_status, significant,
            detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        indicator,
        change.get("previous_score"),
        change["current_score"],
        change.get("change"),
        change["status"],
        int(change.get("significant", False)),
        datetime.now(timezone.utc).isoformat()
    ))

    return cursor.lastrowid


def list_risk_events(limit=50):
    initialize_risk_events()

    with connect() as db:
        rows = db.execute("""
            SELECT *
            FROM risk_change_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


if __name__ == "__main__":
    initialize_risk_events()
    print("PASS: Risk change event database initialized")
    print("Stored events:", len(list_risk_events()))
