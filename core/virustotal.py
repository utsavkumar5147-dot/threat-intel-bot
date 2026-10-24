from rate_limiter import acquire_permission, parse_retry_after, set_provider_cooldown
import base64
import ipaddress
import os
import time

import requests

from ioc_classifier import classify_ioc


API_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 12


def virustotal_lookup(indicator):
    ioc = classify_ioc(indicator)

    if not ioc.get("valid"):
        return {
            "status": "error",
            "message": ioc.get("error", "Invalid indicator")
        }

    if not ioc.get("external_lookup_allowed"):
        return {
            "status": "skipped",
            "message": "External lookup not permitted for this indicator"
        }

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {
            "status": "error",
            "message": "VT_API_KEY is missing"
        }

    kind = ioc["type"]
    value = ioc["value"]

    if kind == "ip":
        endpoint = f"/ip_addresses/{value}"
    elif kind == "domain":
        endpoint = f"/domains/{value}"
    elif kind == "sha256":
        endpoint = f"/files/{value}"
    elif kind == "url":
        url_id = base64.urlsafe_b64encode(
            value.encode("utf-8")
        ).decode("ascii").strip("=")
        endpoint = f"/urls/{url_id}"
    else:
        return {"status": "error", "message": "Unsupported IOC type"}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    for attempt in range(2):
        allowed, wait = acquire_permission("virustotal")

        if not allowed:
            return {
                "status": "rate_limited",
                "retry_after": wait,
                "message": "VirusTotal local request cooldown active"
            }

        try:
            response = requests.get(
                API_BASE + endpoint,
                headers=headers,
                timeout=TIMEOUT
            )

            if response.status_code == 429:
                wait = parse_retry_after(
                    response.headers.get("Retry-After")
                )
                set_provider_cooldown("virustotal", wait)

                return {
                    "status": "rate_limited",
                    "retry_after": wait,
                    "message": "VirusTotal API quota or rate limit reached"
                }

            if response.status_code == 404:
                return {
                    "status": "not_found",
                    "message": "No existing VirusTotal analysis found"
                }

            if response.status_code in (401, 403):
                return {
                    "status": "error",
                    "message": "VirusTotal authentication or access denied"
                }

            if response.status_code >= 500 and attempt == 0:
                time.sleep(2)
                continue

            response.raise_for_status()

            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "status": "completed",
                "provider": "VirusTotal",
                "indicator": value,
                "type": kind,
                "last_analysis_stats": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                },
                "reputation": attributes.get("reputation"),
                "last_analysis_date": attributes.get("last_analysis_date")
            }

        except requests.RequestException as error:
            if attempt == 0:
                time.sleep(2)
                continue
            return {
                "status": "error",
                "message": f"VirusTotal request failed: {type(error).__name__}"
            }
        except (ValueError, TypeError, AttributeError):
            return {
                "status": "error",
                "message": "Invalid VirusTotal response"
            }

    return {
        "status": "error",
        "message": "VirusTotal service temporarily unavailable"
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python virustotal.py <IOC>")
        sys.exit(1)

    print(json.dumps(virustotal_lookup(sys.argv[1]), indent=2))
