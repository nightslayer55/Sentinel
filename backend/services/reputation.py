import os
import requests
from urllib.parse import urlparse


VT_API_URL = "https://www.virustotal.com/api/v3/domains"


def check_reputation(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "status": "unknown",
            "source": "local",
            "finding": "Unable to determine domain",
            "points": 0,
            "evidence_type": "information"
        }

    # Local trusted-domain check
    known_safe_domains = [
        "example.com",
        "google.com",
        "microsoft.com",
        "amazon.com"
    ]

    if hostname.lower() in known_safe_domains:
        return {
            "status": "known_safe",
            "source": "local",
            "finding": "Domain is on the local known-safe list",
            "points": 0,
            "evidence_type": "trust"
        }

    # VirusTotal check
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "status": "unknown",
            "source": "local",
            "finding": "No reputation information available",
            "points": 0,
            "evidence_type": "information"
        }

    try:
        response = requests.get(
            f"{VT_API_URL}/{hostname}",
            headers={
                "x-apikey": api_key
            },
            timeout=10
        )

        if response.status_code == 404:
            return {
                "status": "unknown",
                "source": "VirusTotal",
                "finding": "VirusTotal has no reputation record for this domain",
                "points": 0,
                "evidence_type": "information"
            }

        response.raise_for_status()

        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            return {
                "status": "malicious",
                "source": "VirusTotal",
                "finding": (
                    f"{malicious} security engines flagged this domain as malicious"
                ),
                "points": 40,
                "evidence_type": "risk",
                "details": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                }
            }

        if suspicious > 0:
            return {
                "status": "suspicious",
                "source": "VirusTotal",
                "finding": (
                    f"{suspicious} security engines flagged this domain as suspicious"
                ),
                "points": 20,
                "evidence_type": "risk",
                "details": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                }
            }

        return {
            "status": "clean",
            "source": "VirusTotal",
            "finding": (
                "No malicious or suspicious detections were reported "
                "by the engines checked"
            ),
            "points": 0,
            "evidence_type": "trust",
            "details": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            }
        }

    except requests.RequestException:
        return {
            "status": "unknown",
            "source": "VirusTotal",
            "finding": "Reputation check could not be completed",
            "points": 0,
            "evidence_type": "information"
        }