from app.tools.finding_correlation import correlate_imported_findings, correlation_score
from app.agents.graph import correlate_node


def finding(identifier, source, endpoint, category, evidence, severity="medium"):
    return {
        "id": identifier,
        "method": "GET",
        "endpoint": endpoint,
        "category": category,
        "severity": severity,
        "confidence": 0.75,
        "evidence": [evidence],
        "source_tools": [source],
        "potential_impact": "The issue may affect the API if confirmed.",
        "remediation": f"Fix {source} issue.",
        "status": "imported-needs-review",
    }


def test_correlates_by_endpoint_category_and_evidence() -> None:
    zap = finding("ZAP-1", "owasp-zap-import", "/users/42?full=true", "sql-injection", "Unparameterized SQL user input")
    sonar = finding("SONAR-1", "sonarqube-import", "/users/{id}", "sql-injection-risk", "SQL injection from user input", "high")

    findings = correlate_imported_findings([zap], [sonar])

    assert correlation_score(zap, sonar) > 0.86
    assert len(findings) == 1
    assert findings[0]["status"] == "supported"
    assert findings[0]["severity"] == "high"
    assert findings[0]["source_tools"] == ["owasp-zap-import", "sonarqube-import"]
    assert findings[0]["potential_impact"] == "The issue may affect the API if confirmed."
    assert findings[0]["correlation"]["source_finding_ids"] == ["ZAP-1", "SONAR-1"]


def test_does_not_correlate_different_endpoints() -> None:
    zap = finding("ZAP-1", "owasp-zap-import", "/users/42", "sql-injection", "SQL user input")
    sonar = finding("SONAR-1", "sonarqube-import", "/orders/42", "sql-injection", "SQL user input")
    findings = correlate_imported_findings([zap], [sonar])
    assert len(findings) == 2
    assert all(item["status"] == "imported-needs-review" for item in findings)


def test_does_not_correlate_without_evidence_support() -> None:
    zap = finding("ZAP-1", "owasp-zap-import", "/users/42", "sql-injection", "database query")
    sonar = finding("SONAR-1", "sonarqube-import", "/users/{id}", "sql-injection", "unrelated static observation")
    assert correlation_score(zap, sonar) == 0.85
    assert len(correlate_imported_findings([zap], [sonar])) == 2


def test_active_zap_signal_correlates_with_passive_finding() -> None:
    state = {
        "raw_findings": [
            {
                "source": "passive-http",
                "method": "GET",
                "endpoint": "/users",
                "category": "missing-security-headers",
                "severity": "low",
                "evidence": "A response security header was absent.",
            },
            {
                "source_tools": ["OWASP ZAP"],
                "method": "GET",
                "endpoint": "/users",
                "category": "missing-security-headers",
                "severity": "medium",
                "confidence": 0.85,
                "evidence": ["OWASP ZAP reported a missing security header."],
                "potential_impact": "Missing headers may weaken browser defenses.",
                "remediation": "Return the missing header.",
            },
        ],
        "timeline": [],
    }
    result = correlate_node(state)
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["severity"] == "medium"
    assert finding["status"] == "supported"
    assert finding["source_tools"] == ["OWASP ZAP", "passive-http"]
