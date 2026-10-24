import json
import os
import sys
from datetime import datetime, timezone, timedelta

from ioc_classifier import classify_ioc
from unified_intel import investigate
from threat_scoring import calculate_risk
from investigation_store import (
    save_investigation,
    get_latest_report
)


CACHE_HOURS = 24


def parse_timestamp(value):
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def cached_investigate(indicator, allow_external=False, save_history=True):
    ioc = classify_ioc(indicator)

    if not ioc.get("valid"):
        return {
            "status": "invalid",
            "message": ioc.get("error", "Invalid IOC")
        }

    normalized = ioc["value"]

    # Do not return previously shared intelligence without
    # permission to use externally sourced results.
    if not allow_external:
        report = investigate(normalized, allow_external=False)
        report["risk_assessment"] = calculate_risk(report)
        report["cache_status"] = "not_used"
        return report

    # Never call external providers for non-public indicators.
    if not ioc.get("external_lookup_allowed"):
        report = investigate(normalized, allow_external=False)
        report["risk_assessment"] = calculate_risk(report)
        report["cache_status"] = "not_used"
        return report

    latest = get_latest_report(normalized)

    if latest and latest.get("status") == "completed":
        timestamp = parse_timestamp(
            latest.get("investigated_at")
        )

        if timestamp:
            age = datetime.now(timezone.utc) - timestamp

            if timedelta(0) <= age < timedelta(hours=CACHE_HOURS):
                latest["cache_status"] = "hit"
                latest["cache_age_seconds"] = int(
                    age.total_seconds()
                )
                return latest

    report = investigate(normalized, allow_external=True)
    report["risk_assessment"] = calculate_risk(report)
    report["cache_status"] = "miss"

    if save_history and report.get("status") == "completed":
        report["database_id"] = save_investigation(report)

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cached_intel.py <IOC> [--lookup]")
        sys.exit(1)

    value = sys.argv[1]
    allow = "--lookup" in sys.argv[2:]

    print(json.dumps(
        cached_investigate(value, allow_external=allow),
        indent=2
    ))
