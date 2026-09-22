def calculate_score(findings):
    score = sum(finding.get("points", 0) for finding in findings)

    # Keep the score within 0–100.
    score = max(0, min(score, 100))

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MODERATE"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level
    }