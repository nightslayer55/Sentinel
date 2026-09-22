def build_ai_context(risk_score, risk_level, evidence_summary):
    context = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": []
    }

    all_findings = (
        evidence_summary.get("risk_findings", [])
        + evidence_summary.get("information_findings", [])
        + evidence_summary.get("positive_findings", [])
    )

    for finding in all_findings:
        item = {
    "category": finding.get("category"),
    "finding": finding.get("finding"),
    "explanation": finding.get("explanation"),
    "severity": finding.get("severity"),
    "points": finding.get("points")
}

        if finding.get("details"):
            item["details"] = finding["details"]

        context["findings"].append(item)

    return context