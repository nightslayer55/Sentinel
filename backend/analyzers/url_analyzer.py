from urllib.parse import urlparse
import ipaddress
import re

from services.reputation import check_reputation
from security.scoring import calculate_score
from security.evidence import build_evidence_summary
from security.ai_context import build_ai_context
from services.ai import generate_explanation


def add_finding(
    findings,
    category,
    severity,
    points,
    finding,
    explanation,
    details=None
):
    evidence = {
        "category": category,
        "severity": severity,
        "points": points,
        "finding": finding,
        "explanation": explanation
    }

    if details is not None:
        evidence["details"] = details

    findings.append(evidence)


def analyze_url(url):
    findings = []

    if not url:
        return {
            "valid": False,
            "error": "No URL provided"
        }

    if not re.match(r"^https?://", url, re.IGNORECASE):
        return {
            "valid": False,
            "error": "URL must start with http:// or https://"
        }

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "valid": False,
            "error": "Unable to determine hostname"
        }

    # Detect whether the hostname is an IP address.
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        pass

    # HTTPS check
    if parsed.scheme.lower() != "https":
        add_finding(
            findings,
            "connection",
            "medium",
            10,
            "Connection does not use HTTPS",
            "The URL uses HTTP instead of HTTPS."
        )

    # IP address check
    if is_ip_address:
        add_finding(
            findings,
            "hostname",
            "high",
            20,
            "URL uses an IP address instead of a domain name",
            "Using an IP address directly can be unusual for a normal public website."
        )

    # Suspicious URL patterns
    suspicious_patterns = [
        "login",
        "verify",
        "account",
        "password",
        "secure",
        "update"
    ]

    matched_patterns = [
        pattern
        for pattern in suspicious_patterns
        if pattern in url.lower()
    ]

    if len(matched_patterns) >= 2:
        add_finding(
            findings,
            "url_structure",
            "medium",
            15,
            "Multiple suspicious URL indicators detected",
            "The URL contains several terms or patterns commonly seen "
            "in links that attempt to direct users toward account or "
            "verification pages.",
            {
                "matched_patterns": matched_patterns
            }
        )

    # Long URL check
    if len(url) > 200:
        add_finding(
            findings,
            "url_structure",
            "low",
            5,
            "Unusually long URL",
            "The URL is longer than 200 characters."
        )

    # @ symbol check
    if "@" in url or "%40" in url.lower():
        add_finding(
            findings,
            "url_structure",
            "high",
            20,
            "URL contains an @ symbol",
            "An @ symbol can be used to make a URL appear to contain a trusted name."
        )

    if "@" in url:
        before_at = url.split("@")[0]

        if "." in before_at:
            add_finding(
                findings,
                "url_structure",
                "high",
                15,
                "URL contains domain-like text before the @ symbol",
                "Text before the @ symbol may make the URL appear to belong to another domain."
            )

    # Subdomain check.
    # Only perform this check for actual domain names.
    # IP addresses such as 192.168.1.100 must not be treated
    # as having four subdomains.
    if not is_ip_address:
        hostname_parts = hostname.split(".")

        if len(hostname_parts) >= 4:
            add_finding(
                findings,
                "hostname",
                "medium",
                10,
                "Hostname contains many subdomains",
                "The hostname contains four or more dot-separated parts."
            )

    # Non-standard port check
    if parsed.port is not None and parsed.port not in (80, 443):
        add_finding(
            findings,
            "connection",
            "medium",
            10,
            "URL uses a non-standard port",
            f"The URL uses port {parsed.port}."
        )

    # Reputation check
    reputation = check_reputation(url)

    severity = "info"

    if reputation["points"] >= 20:
        severity = "high"
    elif reputation["points"] > 0:
        severity = "medium"

    reputation_explanation = (
        f"Reputation source: {reputation['source']}"
    )

    if "details" in reputation:
        reputation_explanation += (
            f" | Analysis details: {reputation['details']}"
        )

    add_finding(
        findings,
        "reputation",
        severity,
        reputation["points"],
        reputation["finding"],
        reputation_explanation,
        reputation.get("details")
    )

    # Calculate deterministic risk score
    risk = calculate_score(findings)

    # Build evidence summary
    evidence_summary = build_evidence_summary(findings)

    # Build context supplied to the AI
    ai_context = build_ai_context(
        risk["score"],
        risk["level"],
        evidence_summary
    )

    # AI only explains the evidence.
    # It does not calculate or modify the score.
    explanation = generate_explanation(
        risk["score"],
        risk["level"],
        evidence_summary
    )

    return {
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "valid": True,
        "evidence": findings,
        "evidence_summary": evidence_summary,
        "ai_context": ai_context,
        "explanation": explanation
    }