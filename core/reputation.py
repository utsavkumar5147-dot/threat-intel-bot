from rate_limiter import acquire_permission, parse_retry_after, set_provider_cooldown

import os
import ipaddress
import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"

def check_reputation(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "Invalid IP address"}

    if not address.is_global:
        return {
            "ip": ip,
            "status": "Skipped",
            "reason": "Not a globally routable public IP"
        }

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY is missing"}

    allowed, wait = acquire_permission("abuseipdb")

    if not allowed:
        return {
            "status": "rate_limited",
            "retry_after": wait,
            "message": "AbuseIPDB local request cooldown active"
        }

    try:
        response = requests.get(
            API_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=10
        )

        if response.status_code == 429:
            wait = parse_retry_after(
                response.headers.get("Retry-After")
            )
            set_provider_cooldown("abuseipdb", wait)

            return {
                "status": "rate_limited",
                "retry_after": wait,
                "message": "AbuseIPDB API quota or rate limit reached"
            }

        response.raise_for_status()
        data = response.json()["data"]

        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain")
        }

    except requests.Timeout:
        return {"error": "AbuseIPDB request timed out"}
    except requests.HTTPError:
        return {"error": "AbuseIPDB returned an HTTP error"}
    except requests.RequestException:
        return {"error": "AbuseIPDB network request failed"}
    except (ValueError, KeyError, TypeError):
        return {"error": "Invalid AbuseIPDB response"}

if __name__ == "__main__":
    print(check_reputation("127.0.0.1"))
