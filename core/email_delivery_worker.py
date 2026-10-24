import json
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE))

from investigation_store import connect
from email_dispatcher import initialize_email_delivery, queue_email_alerts, now
from gmail_sender import send_gmail_alert

CONFIG = Path.home() / ".config/threat-intel-bot/gmail-alerts.json"


def process_one_email():
    settings = json.loads(CONFIG.read_text(encoding="utf-8"))

    if settings.get("enabled") is not True:
        print("Email automation disabled. Nothing sent.")
        return False

    sender = settings.get("sender")
    recipient = settings.get("recipient")

    if not sender or not recipient:
        raise ValueError("Gmail sender or recipient is missing")

    initialize_email_delivery()
    queue_email_alerts()

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT e.id, n.indicator, n.title,
                   n.message, n.severity
            FROM email_deliveries e
            JOIN notifications n
              ON n.id = e.notification_id
            WHERE e.status = 'pending'
            ORDER BY e.id
            LIMIT 1
        """).fetchone()

        if row is None:
            print("No pending email alerts.")
            return False

        db.execute("""
            UPDATE email_deliveries
            SET status = 'sending',
                attempts = attempts + 1,
                updated_at = ?
            WHERE id = ?
        """, (now(), row["id"]))

        alert = dict(row)

    try:
        message_id = send_gmail_alert(
            sender=sender,
            recipient=recipient,
            indicator=alert["indicator"],
            title=alert["title"],
            message=alert["message"],
            severity=alert["severity"]
        )

        if not message_id:
            raise RuntimeError("Gmail did not confirm message submission")

    except Exception as error:
        with connect() as db:
            db.execute("""
                UPDATE email_deliveries
                SET status = 'needs_review',
                    updated_at = ?,
                    last_error = ?
                WHERE id = ? AND status = 'sending'
            """, (now(), type(error).__name__, alert["id"]))

        print("Email delivery requires review:", type(error).__name__)
        return False

    with connect() as db:
        db.execute("""
            UPDATE email_deliveries
            SET status = 'sent',
                sent_at = ?,
                updated_at = ?,
                last_error = NULL
            WHERE id = ? AND status = 'sending'
        """, (now(), now(), alert["id"]))

    print("PASS: Gmail alert submitted successfully")
    print("Indicator:", alert["indicator"])
    return True


if __name__ == "__main__":
    process_one_email()
