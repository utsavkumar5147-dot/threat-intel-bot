import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "investigations.db"
)


def database_path():
    return Path(
        os.environ.get("THREAT_BOT_DB", str(DEFAULT_DB))
    ).expanduser()


def connect():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        fd = os.open(
            str(path),
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600
        )
        os.close(fd)

    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")

    return connection


def initialize():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER,
                risk_level TEXT,
                investigated_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ioc_history
            ON investigations(indicator, investigated_at DESC)
        """)


def save_investigation(report):
    if not isinstance(report, dict):
        raise ValueError("Report must be a dictionary")

    indicator = report.get("indicator")
    ioc_type = report.get("type")

    if not isinstance(indicator, str) or not indicator:
        raise ValueError("Missing indicator")

    if not isinstance(ioc_type, str) or not ioc_type:
        raise ValueError("Missing IOC type")

    assessment = report.get("risk_assessment") or {}

    timestamp = report.get("investigated_at")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    initialize()

    with connect() as db:
        cursor = db.execute("""
            INSERT INTO investigations (
                indicator, ioc_type, status,
                risk_score, risk_level,
                investigated_at, report_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            indicator,
            ioc_type,
            report.get("status", "unknown"),
            assessment.get("risk_score"),
            assessment.get("risk_level"),
            timestamp,
            json.dumps(report)
        ))

        return cursor.lastrowid


def get_history(indicator, limit=20):
    initialize()

    limit = max(1, min(int(limit), 100))

    with connect() as db:
        rows = db.execute("""
            SELECT id, indicator, ioc_type, status,
                   risk_score, risk_level,
                   investigated_at
            FROM investigations
            WHERE indicator = ?
            ORDER BY id DESC
            LIMIT ?
        """, (indicator, limit)).fetchall()

    return [dict(row) for row in rows]


def get_latest_report(indicator):
    initialize()

    with connect() as db:
        row = db.execute("""
            SELECT report_json
            FROM investigations
            WHERE indicator = ?
            ORDER BY id DESC
            LIMIT 1
        """, (indicator,)).fetchone()

    return json.loads(row["report_json"]) if row else None


if __name__ == "__main__":
    initialize()
    print("SQLite database initialized:", database_path())
