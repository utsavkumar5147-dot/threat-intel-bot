import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "core"

sys.path.insert(0, str(CORE))

from investigation_store import connect, initialize
from ioc_monitor import initialize_monitor, list_monitored
from notifications import initialize_notifications, list_notifications
from job_queue import initialize_queue


from retry_policy import initialize_retry_policy

def create_app():
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

    initialize()
    initialize_queue()
    initialize_retry_policy()
    initialize_monitor()
    initialize_notifications()

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/classify")
    def classify():
        from ioc_classifier import classify_ioc

        if not request.is_json:
            return jsonify({
                "status": "error",
                "message": "JSON body required"
            }), 415

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "message": "Invalid JSON object"
            }), 400

        result = classify_ioc(data.get("indicator"))

        return jsonify(result), 200 if result.get("valid") else 400

    @app.post("/api/investigate")
    def submit_investigation():
        from job_queue import enqueue

        if not request.is_json:
            return jsonify({
                "status": "error",
                "message": "JSON body required"
            }), 415

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "message": "Invalid JSON object"
            }), 400

        indicator = data.get("indicator")
        consent = data.get("allow_external") is True

        if not consent:
            return jsonify({
                "status": "rejected",
                "reason": "Explicit external lookup permission required"
            }), 403

        outcome = enqueue(
            indicator,
            allow_external=True
        )

        status_code = (
            202 if outcome["status"] == "queued"
            else 200 if outcome["status"] == "duplicate"
            else 400
        )

        return jsonify(outcome), status_code

    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "application": "Automated Threat Intelligence & IOC Enrichment Bot"
        })

    @app.get("/api/overview")
    def overview():
        with connect() as db:
            investigations = db.execute(
                "SELECT COUNT(*) FROM investigations"
            ).fetchone()[0]

            monitored = db.execute(
                "SELECT COUNT(*) FROM monitored_iocs"
            ).fetchone()[0]

            notifications = db.execute(
                "SELECT COUNT(*) FROM notifications"
            ).fetchone()[0]

            pending = db.execute(
                """
                SELECT COUNT(*) FROM investigation_jobs
                WHERE status IN ('pending', 'running')
                """
            ).fetchone()[0]

        return jsonify({
            "investigations": investigations,
            "monitored_iocs": monitored,
            "notifications": notifications,
            "active_jobs": pending
        })

    @app.get("/api/investigations")
    def investigations():
        with connect() as db:
            rows = db.execute("""
                SELECT id, indicator, ioc_type, status,
                       risk_score, risk_level, investigated_at
                FROM investigations
                ORDER BY id DESC
                LIMIT 100
            """).fetchall()

        return jsonify([dict(row) for row in rows])

    @app.get("/api/monitored")
    def monitored():
        return jsonify(list_monitored())

    @app.get("/api/notifications")
    def notifications():
        return jsonify(list_notifications())

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5050,
        debug=False
    )
