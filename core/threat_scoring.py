import json


def calculate_risk(report):
    providers = report.get("providers", {})
    evidence = []
    scores = []

    abuse = providers.get("abuseipdb", {})
    if abuse.get("status") == "completed":
        result = abuse.get("result", {})
        score = result.get("abuse_score")

        if isinstance(score, (int, float)) and not isinstance(score, bool):
            score = max(0, min(100, float(score)))
            scores.append(score)
            evidence.append({
                "provider": "AbuseIPDB",
                "score": round(score, 1),
                "reason": "Abuse confidence score reported by AbuseIPDB"
            })

    vt = providers.get("virustotal", {})
    if vt.get("status") == "completed":
        stats = vt.get("last_analysis_stats", {})
        malicious = stats.get("malicious")
        suspicious = stats.get("suspicious")
        harmless = stats.get("harmless")
        undetected = stats.get("undetected")

        counts = [malicious, suspicious, harmless, undetected]

        if all(
            isinstance(n, int) and not isinstance(n, bool) and n >= 0
            for n in counts
        ):
            total = sum(counts)

            if total > 0:
                # Project-defined heuristic, not a VirusTotal score.
                vt_score = min(
                    100,
                    (malicious * 100 + suspicious * 50) / total
                )
                scores.append(vt_score)
                evidence.append({
                    "provider": "VirusTotal",
                    "score": round(vt_score, 1),
                    "reason": (
                        f"{malicious} malicious and {suspicious} suspicious "
                        f"detections out of {total} analysis results"
                    )
                })

    if not scores:
        return {
            "risk_score": None,
            "risk_level": "Unknown",
            "evidence": evidence,
            "confidence": "Insufficient evidence",
            "method": "Project heuristic v1"
        }

    # Highest observed provider risk is retained to avoid hiding
    # strong detections through averaging.
    final_score = round(max(scores))

    if final_score >= 70:
        level = "High"
    elif final_score >= 40:
        level = "Elevated"
    elif final_score >= 20:
        level = "Guarded"
    else:
        level = "Low"

    return {
        "risk_score": final_score,
        "risk_level": level,
        "evidence": evidence,
        "confidence": (
            "Multiple providers" if len(scores) > 1
            else "Single provider"
        ),
        "method": "Project heuristic v1",
        "note": (
            "This score summarizes available reputation evidence. "
            "A low score does not prove an indicator is safe."
        )
    }


if __name__ == "__main__":
    import sys
    from unified_intel import investigate

    if len(sys.argv) < 2:
        print("Usage: python threat_scoring.py <IOC> [--lookup]")
        sys.exit(1)

    indicator = sys.argv[1]
    allow = "--lookup" in sys.argv[2:]

    report = investigate(indicator, allow_external=allow)
    report["risk_assessment"] = calculate_risk(report)

    print(json.dumps(report, indent=2))
