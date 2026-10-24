from core.threat_scoring import calculate_risk


def abuse_report(score):
    return {
        "providers": {
            "abuseipdb": {
                "status": "completed",
                "result": {"abuse_score": score}
            }
        }
    }


def vt_report(malicious, suspicious, harmless, undetected):
    return {
        "providers": {
            "virustotal": {
                "status": "completed",
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                }
            }
        }
    }


def test_unknown_when_no_evidence():
    result = calculate_risk({"providers": {}})
    assert result["risk_score"] is None
    assert result["risk_level"] == "Unknown"


def test_low_risk():
    assert calculate_risk(abuse_report(10))["risk_level"] == "Low"


def test_guarded_risk():
    assert calculate_risk(abuse_report(25))["risk_level"] == "Guarded"


def test_elevated_risk():
    assert calculate_risk(abuse_report(50))["risk_level"] == "Elevated"


def test_high_risk():
    assert calculate_risk(abuse_report(85))["risk_level"] == "High"


def test_score_clamped_to_100():
    assert calculate_risk(abuse_report(150))["risk_score"] == 100


def test_invalid_boolean_score_ignored():
    assert calculate_risk(abuse_report(True))["risk_level"] == "Unknown"


def test_virustotal_scoring():
    result = calculate_risk(vt_report(3, 2, 5, 0))
    assert result["risk_score"] == 40
    assert result["risk_level"] == "Elevated"


def test_virustotal_zero_total():
    result = calculate_risk(vt_report(0, 0, 0, 0))
    assert result["risk_level"] == "Unknown"


def test_highest_provider_score_wins():
    report = abuse_report(90)
    report["providers"].update(vt_report(0, 0, 10, 0)["providers"])

    result = calculate_risk(report)

    assert result["risk_score"] == 90
    assert result["confidence"] == "Multiple providers"
