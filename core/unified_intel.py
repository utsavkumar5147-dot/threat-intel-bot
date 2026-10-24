import json
import sys
from datetime import datetime, timezone

from ioc_classifier import classify_ioc
from reputation import check_reputation
from virustotal import virustotal_lookup


def investigate(indicator, allow_external=False, previous_report=None):
    ioc = classify_ioc(indicator)

    if not ioc.get("valid"):
        return {
            "status": "invalid",
            "message": ioc.get("error", "Invalid indicator"),
            "providers": {}
        }

    report = {
        "indicator": ioc["value"],
        "type": ioc["type"],
        "classification": ioc["classification"],
        "investigated_at": datetime.now(timezone.utc).isoformat(),
        "status": "validated",
        "providers": {}
    }

    if not ioc.get("external_lookup_allowed"):
        report["status"] = "skipped"
        report["message"] = "External reputation lookups are disabled for this indicator"
        return report

    if not allow_external:
        report["status"] = "awaiting_consent"
        report["message"] = (
            "External lookups require explicit permission to share "
            "this indicator with intelligence providers"
        )
        return report

    previous_providers = {}

    if (
        isinstance(previous_report, dict)
        and previous_report.get("indicator") == ioc["value"]
        and previous_report.get("type") == ioc["type"]
    ):
        previous_providers = previous_report.get("providers", {})

    if not isinstance(previous_providers, dict):
        previous_providers = {}

    if ioc["type"] == "ip":
        saved_abuse = previous_providers.get("abuseipdb")

        if (
            isinstance(saved_abuse, dict)
            and saved_abuse.get("status") == "completed"
        ):
            report["providers"]["abuseipdb"] = saved_abuse
        else:
            abuse = check_reputation(ioc["value"])

            if abuse.get("status") == "rate_limited":
                abuse_status = "rate_limited"
            elif "error" in abuse:
                abuse_status = "error"
            elif abuse.get("status") == "Skipped":
                abuse_status = "skipped"
            else:
                abuse_status = "completed"

            report["providers"]["abuseipdb"] = {
                "status": abuse_status,
                "result": abuse
            }

    saved_vt = previous_providers.get("virustotal")

    if (
        isinstance(saved_vt, dict)
        and saved_vt.get("status") == "completed"
    ):
        report["providers"]["virustotal"] = saved_vt
    else:
        report["providers"]["virustotal"] = virustotal_lookup(
            ioc["value"]
        )

    statuses = [
        result.get("status")
        for result in report["providers"].values()
    ]

    if statuses and all(status == "completed" for status in statuses):
        report["status"] = "completed"
    elif "completed" in statuses:
        report["status"] = "partial"
    else:
        report["status"] = "no_successful_lookup"

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python unified_intel.py <IOC> [--lookup]")
        sys.exit(1)

    value = sys.argv[1]
    allow = "--lookup" in sys.argv[2:]

    print(json.dumps(
        investigate(value, allow_external=allow),
        indent=2
    ))
