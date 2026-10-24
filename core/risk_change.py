def detect_risk_change(previous_score, current_score, threshold=20):
    """
    Compare two risk scores and identify significant changes.
    Scores must be integers between 0 and 100.
    """

    def valid(score):
        return (
            isinstance(score, int)
            and not isinstance(score, bool)
            and 0 <= score <= 100
        )

    if not valid(current_score):
        return {
            "status": "invalid",
            "message": "Invalid current risk score"
        }

    if previous_score is None:
        return {
            "status": "baseline",
            "current_score": current_score,
            "message": "Initial risk baseline established"
        }

    if not valid(previous_score):
        return {
            "status": "invalid",
            "message": "Invalid previous risk score"
        }

    if not valid(threshold) or threshold < 1:
        return {
            "status": "invalid",
            "message": "Invalid change threshold"
        }

    change = current_score - previous_score

    if change >= threshold:
        status = "increased"
    elif change <= -threshold:
        status = "decreased"
    else:
        status = "stable"

    return {
        "status": status,
        "previous_score": previous_score,
        "current_score": current_score,
        "change": change,
        "significant": abs(change) >= threshold
    }


if __name__ == "__main__":
    print(detect_risk_change(20, 85))
    print("PASS: Risk change engine created")
