import ollama


def generate_explanation(risk_score, risk_level, evidence_summary):
    """
    Ask the local Llama model to explain Sentinel's
    deterministic security findings.

    The AI does NOT calculate or modify the risk score.
    """

    risk_findings = evidence_summary.get("risk_findings", [])
    information_findings = evidence_summary.get("information_findings", [])
    positive_findings = evidence_summary.get("positive_findings", [])

    prompt = f"""
You are Sentinel's security explanation assistant.

Your job is ONLY to explain the evidence Sentinel already found.

FINAL ASSESSMENT:
Risk score: {risk_score}/100
Risk level: {risk_level}

RISK FINDINGS:
{risk_findings}

INFORMATIONAL FINDINGS:
{information_findings}

POSITIVE FINDINGS:
{positive_findings}

STRICT RULES:
1. Do not calculate or change the risk score.
2. Do not change the risk level.
3. Do not invent findings.
4. Do not mention a security feature unless it appears in the findings.
5. If HTTPS is not listed as a finding, do NOT discuss HTTPS.
6. If there are no risk findings, say that no risk indicators contributed
   points to the score.
7. Informational findings do NOT contribute risk points.
8. Do not call a URL malicious, phishing, or dangerous unless the evidence
   explicitly supports that conclusion.
9. Do not talk about the user's internet connection, online activity,
   accounts, or personal information.
10. Talk only about the URL and the evidence provided.
11. Do not give advice unrelated to the provided evidence.
12. Use simple language suitable for an ordinary internet user.
13. Keep the explanation under 100 words.
14. If a finding has points greater than 0, explicitly say it contributed those points.
15. If a finding has 0 points, explicitly say it did not contribute to the risk score.
16. Never say that no risk indicators contributed if any finding has points greater than 0.

Write only the explanation.
"""

    try:
        response = ollama.chat(
            model="llama3.2:3b",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return response["message"]["content"]

    except Exception as e:
        print("OLLAMA ERROR:", repr(e))

        return generate_mock_explanation(
            risk_score,
            risk_level,
            evidence_summary
        )


def generate_mock_explanation(risk_score, risk_level, evidence_summary):
    risk_findings = evidence_summary.get("risk_findings", [])
    information_findings = evidence_summary.get("information_findings", [])
    positive_findings = evidence_summary.get("positive_findings", [])

    explanation_parts = []

    explanation_parts.append(
        f"Sentinel assigned this URL a {risk_level} risk level "
        f"with a score of {risk_score}/100."
    )

    if risk_findings:
        explanation_parts.append(
            f"{len(risk_findings)} finding(s) contributed to the risk score."
        )

        for finding in risk_findings:
            explanation_parts.append(
                f"{finding['finding']}. "
                f"{finding['explanation']} "
                f"This contributed {finding['points']} risk points."
            )

    for finding in information_findings:
        if finding["category"] == "reputation":
            details = finding.get("details")

            if details:
                explanation_parts.append(
                    f"The reputation check reported "
                    f"{details.get('malicious', 0)} malicious, "
                    f"{details.get('suspicious', 0)} suspicious, "
                    f"{details.get('harmless', 0)} harmless, and "
                    f"{details.get('undetected', 0)} undetected results."
                )
            else:
                explanation_parts.append(finding["finding"])

    for finding in information_findings:
        if finding["category"] != "reputation":
            explanation_parts.append(finding["finding"])

    for finding in positive_findings:
        explanation_parts.append(
            f"{finding['finding']}. "
            f"This reduced the risk score by "
            f"{abs(finding['points'])} points."
        )

    if not risk_findings:
        explanation_parts.append(
            "No risk indicators contributed points to the current assessment."
        )

    return " ".join(explanation_parts)