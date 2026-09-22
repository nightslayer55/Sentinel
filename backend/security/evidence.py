def build_evidence_summary(findings):
    summary = {
        "total_findings": len(findings),
        "risk_findings": [],
        "information_findings": [],
        "positive_findings": []
    }

    for finding in findings:
        points = finding.get("points", 0)

        if points > 0:
            summary["risk_findings"].append(finding)

        elif points < 0:
            summary["positive_findings"].append(finding)

        else:
            summary["information_findings"].append(finding)

    return summary