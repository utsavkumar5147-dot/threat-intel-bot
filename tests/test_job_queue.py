import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from investigation_store import connect
from job_queue import enqueue, claim_next, recover_interrupted_jobs
from retry_policy import initialize_retry_policy


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_BOT_DB", str(tmp_path / "test.db"))
    initialize_retry_policy()
    yield


def test_public_ip_queued(isolated_db):
    result = enqueue("8.8.8.8", allow_external=True)
    assert result["status"] == "queued"
    assert isinstance(result["job_id"], int)


def test_external_consent_required(isolated_db):
    result = enqueue("8.8.8.8")
    assert result["status"] == "rejected"
    assert "permission" in result["reason"].lower()


def test_private_ip_rejected(isolated_db):
    result = enqueue("192.168.1.1", allow_external=True)
    assert result["status"] == "rejected"


def test_domain_rejected(isolated_db):
    result = enqueue("example.com", allow_external=True)
    assert result["status"] == "rejected"


def test_invalid_ip_rejected(isolated_db):
    result = enqueue("999.999.999.999", allow_external=True)
    assert result["status"] == "rejected"


def test_duplicate_active_job(isolated_db):
    first = enqueue("8.8.8.8", allow_external=True)
    second = enqueue("8.8.8.8", allow_external=True)

    assert first["status"] == "queued"
    assert second["status"] == "duplicate"
    assert second["job_id"] == first["job_id"]


def test_claim_next_job(isolated_db):
    created = enqueue("8.8.8.8", allow_external=True)
    claimed = claim_next()

    assert claimed is not None
    assert claimed["id"] == created["job_id"]

    with connect() as db:
        row = db.execute(
            "SELECT status, attempts FROM investigation_jobs WHERE id = ?",
            (created["job_id"],)
        ).fetchone()

    assert row["status"] == "running"
    assert row["attempts"] == 1


def test_recover_interrupted_job(isolated_db):
    created = enqueue("8.8.8.8", allow_external=True)
    claim_next()

    recovered = recover_interrupted_jobs()

    assert recovered == 1

    with connect() as db:
        row = db.execute(
            "SELECT status, attempts FROM investigation_jobs WHERE id = ?",
            (created["job_id"],)
        ).fetchone()

    assert row["status"] == "pending"
    assert row["attempts"] == 1
