from analyzers.url_analyzer import analyze_url


def test_normal_https():
    result = analyze_url("https://example.com")

    assert result["valid"] is True
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"


def test_http():
    result = analyze_url("http://example.com")

    assert result["valid"] is True
    assert result["risk_score"] == 10


def test_ip_address():
    result = analyze_url("http://192.168.1.100/login")

    assert result["valid"] is True
    assert result["risk_score"] == 30


def test_suspicious_patterns():
    result = analyze_url(
        "https://example.com/login/verify/account"
    )

    assert result["valid"] is True
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW"


def test_at_symbol():
    result = analyze_url(
        "https://google.com@example.com"
    )

    assert result["valid"] is True
    assert result["risk_score"] == 35


def test_long_url():
    url = "https://example.com/" + ("a" * 201)

    result = analyze_url(url)

    assert result["valid"] is True
    assert result["risk_score"] == 5

def test_many_subdomains():
    result = analyze_url(
        "https://a.b.c.example.com"
    )

    assert result["valid"] is True
    assert result["risk_score"] == 10


def test_non_standard_port():
    result = analyze_url(
        "https://example.com:8080"
    )

    assert result["valid"] is True
    assert result["risk_score"] == 10


def test_invalid_url():
    result = analyze_url(
        "example.com"
    )

    assert result["valid"] is False


def test_empty_url():
    result = analyze_url("")

    assert result["valid"] is False

def test_suspicious_patterns_are_recorded():
    result = analyze_url(
        "https://example.com/login/verify/account"
    )

    finding = next(
        item for item in result["evidence"]
        if item["category"] == "url_structure"
    )

    assert finding["points"] == 15
    assert finding["details"]["matched_patterns"] == [
        "login",
        "verify",
        "account"
    ]


def test_ip_address_does_not_trigger_subdomain_finding():
    result = analyze_url(
        "http://192.168.1.100/login"
    )

    categories = [
        item["category"]
        for item in result["evidence"]
    ]

    assert categories.count("hostname") == 1


def test_at_symbol_evidence():
    result = analyze_url(
        "https://google.com@example.com"
    )

    findings = result["evidence"]

    at_finding = next(
        item for item in findings
        if "@" in item["finding"]
    )

    assert at_finding["points"] == 20