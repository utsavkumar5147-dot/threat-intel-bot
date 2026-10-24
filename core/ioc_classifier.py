import ipaddress
import re
from urllib.parse import urlsplit


SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def classify_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if address.is_loopback:
        category = "loopback"
    elif address.is_global:
        category = "public"
    elif address.is_private:
        category = "private_or_reserved"
    else:
        category = "special_use"

    return {
        "valid": True,
        "type": "ip",
        "value": str(address),
        "classification": category,
        "external_lookup_allowed": address.is_global
    }


def normalize_domain(value):
    try:
        ascii_name = value.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None

    if len(ascii_name) > 253 or "." not in ascii_name:
        return None

    labels = ascii_name.split(".")

    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None

    if labels[-1].isdigit() or len(labels[-1]) < 2:
        return None

    return ascii_name


def classify_ioc(raw_value):
    if not isinstance(raw_value, str):
        return {"valid": False, "error": "Indicator must be text"}

    value = raw_value.strip()

    if not value or len(value) > 2048:
        return {"valid": False, "error": "Invalid indicator length"}

    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return {"valid": False, "error": "Control characters are not allowed"}

    if SHA256_PATTERN.fullmatch(value):
        return {
            "valid": True,
            "type": "sha256",
            "value": value.lower(),
            "classification": "file_hash",
            "external_lookup_allowed": True
        }

    ip_result = classify_ip(value)
    if ip_result:
        return ip_result

    if "://" in value:
        try:
            parsed = urlsplit(value)

            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError("Unsupported URL scheme")

            if parsed.username is not None or parsed.password is not None:
                raise ValueError("URLs containing credentials are not accepted")

            hostname = parsed.hostname
            if not hostname:
                raise ValueError("Missing hostname")

            # Accessing port also validates its numeric range.
            port = parsed.port

            host_ip = classify_ip(hostname)
            domain = normalize_domain(hostname) if not host_ip else None

            if not host_ip and not domain:
                raise ValueError("Invalid hostname")

            normalized_host = (
                f"[{host_ip['value']}]"
                if host_ip and ":" in host_ip["value"]
                else host_ip["value"] if host_ip else domain
            )

            normalized = f"{parsed.scheme.lower()}://{normalized_host}"
            if port is not None:
                normalized += f":{port}"
            normalized += parsed.path or "/"
            if parsed.query:
                normalized += "?" + parsed.query

            return {
                "valid": True,
                "type": "url",
                "value": normalized,
                "classification": "web_url",
                "host": host_ip["value"] if host_ip else domain,
                "external_lookup_allowed": (
                    host_ip["external_lookup_allowed"] if host_ip else True
                ),
                "warning": "URLs may contain sensitive query parameters"
            }
        except (ValueError, UnicodeError) as error:
            return {"valid": False, "error": str(error)}

    domain = normalize_domain(value)
    if domain:
        return {
            "valid": True,
            "type": "domain",
            "value": domain,
            "classification": "domain_name",
            "external_lookup_allowed": True
        }

    return {
        "valid": False,
        "error": "Unsupported or malformed IOC"
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python ioc_classifier.py <indicator>")
        sys.exit(1)

    print(json.dumps(classify_ioc(sys.argv[1]), indent=2))
