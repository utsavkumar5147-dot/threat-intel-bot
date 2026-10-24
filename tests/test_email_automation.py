import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))


@pytest.fixture
def email_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "THREAT_BOT_DB",
        str(tmp_path / "test_email.db")
    )

    import email_alert_service as service
    import email_delivery_worker as worker

    config = tmp_path / "gmail-alerts.json"
    config.write_text(json.dumps({
        "sender": "sender@example.com",
        "recipient": "recipient@example.com",
        "enabled": True
    }))

    monkeypatch.setattr(service, "CONFIG", config)
    monkeypatch.setattr(worker, "CONFIG", config)

    return service, worker, config


def create_test_alert():
    from risk_change import detect_risk_change
    from notifications import create_notification

    return create_notification(
        "203.0.113.10",
        detect_risk_change(0, 85)
    )


def get_delivery():
    from investigation_store import connect

    with connect() as db:
        return db.execute("""
            SELECT status, attempts
            FROM email_deliveries
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()


def test_high_risk_alert_sent_once(email_environment):
    service, worker, _ = email_environment
    create_test_alert()

    with patch.object(
        worker,
        "send_gmail_alert",
        return_value="mock-gmail-id"
    ) as mock_send:
        assert service.check_alerts() is True
        assert service.check_alerts() is False
        mock_send.assert_called_once()

    row = get_delivery()

    assert row["status"] == "sent"
    assert row["attempts"] == 1


def test_gmail_failure_requires_review(email_environment):
    service, worker, _ = email_environment
    create_test_alert()

    with patch.object(
        worker,
        "send_gmail_alert",
        side_effect=ConnectionError("Simulated outage")
    ) as mock_send:
        assert service.check_alerts() is False
        assert service.check_alerts() is False
        mock_send.assert_called_once()

    row = get_delivery()

    assert row["status"] == "needs_review"
    assert row["attempts"] == 1


def test_disabled_email_sends_nothing(email_environment):
    service, worker, config = email_environment
    create_test_alert()

    config.write_text(json.dumps({
        "sender": "sender@example.com",
        "recipient": "recipient@example.com",
        "enabled": False
    }))

    with patch.object(worker, "send_gmail_alert") as mock_send:
        assert service.check_alerts() is False
        mock_send.assert_not_called()


def test_no_notification_sends_nothing(email_environment):
    service, worker, _ = email_environment

    with patch.object(worker, "send_gmail_alert") as mock_send:
        assert service.check_alerts() is False
        mock_send.assert_not_called()
