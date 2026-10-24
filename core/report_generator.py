import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ioc_classifier import classify_ioc

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


def generate_report(investigation):
    """Generate a structured JSON report from an investigation."""

    if not isinstance(investigation, dict):
        raise ValueError("Investigation must be a dictionary")

    indicator = investigation.get("indicator")
    ioc = classify_ioc(indicator)

    if not ioc.get("valid"):
        raise ValueError("Invalid IOC")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    safe_indicator = re.sub(
        r"[^a-zA-Z0-9_-]", "_", ioc["value"]
    )[:80]

    filename = (
        f"investigation_{safe_indicator}_"
        f"{timestamp.strftime('%Y%m%d_%H%M%S_%f')}.json"
    )

    report = {
        "report_type": "IOC Threat Intelligence Investigation",
        "generated_at": timestamp.isoformat(),
        "indicator": ioc["value"],
        "ioc_type": ioc["type"],
        "classification": ioc.get("classification"),
        "investigation_status": investigation.get("status"),
        "investigated_at": investigation.get("investigated_at"),
        "risk_assessment": investigation.get("risk_assessment", {}),
        "providers": investigation.get("providers", {}),
        "cache_status": investigation.get("cache_status"),
        "source": "Automated Threat Intelligence & IOC Enrichment Bot"
    }

    path = REPORT_DIR / filename

    with path.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=4, default=str)

    return {
        "status": "generated",
        "path": str(path),
        "indicator": ioc["value"]
    }


if __name__ == "__main__":
    print("PASS: Investigation report generator created")
