import json

import pytest

from app.tools.sonarqube_importer import import_sonarqube_results, parse_sonarqube_results


SONAR_REPORT = {
    "issues": [
        {
            "key": "issue-1",
            "rule": "python:S3649",
            "severity": "CRITICAL",
            "status": "CONFIRMED",
            "component": "api:routes/users.py",
            "line": 42,
            "message": "SQL injection risk in GET /users/42 caused by unparameterized user input",
        }
    ]
}


def test_parse_sonarqube_results_normalizes_issues() -> None:
    findings = parse_sonarqube_results(json.dumps(SONAR_REPORT))
    assert findings == [
        {
            "id": "SONAR-issue-1",
            "method": "GET",
            "endpoint": "/users/42",
            "category": "sql-injection-risk-in-get-users-42-caused-by-unparameterized-user-input",
            "severity": "high",
            "confidence": 0.85,
            "evidence": [
                "SQL injection risk in GET /users/42 caused by unparameterized user input",
                "Static analysis location: api:routes/users.py:42",
            ],
            "source_tools": ["sonarqube-import"],
            "remediation": "Review SonarQube rule python:S3649 and apply its recommended secure coding remediation.",
            "status": "imported-needs-review",
        }
    ]


def test_import_sonarqube_results_reads_file(tmp_path) -> None:
    path = tmp_path / "sonar.json"
    path.write_text(json.dumps(SONAR_REPORT), encoding="utf-8")
    assert import_sonarqube_results(path)[0]["id"] == "SONAR-issue-1"


@pytest.mark.parametrize("content", [b"invalid", b"{}", b"[]"])
def test_parse_sonarqube_results_rejects_invalid_reports(content: bytes) -> None:
    with pytest.raises(ValueError, match="SonarQube"):
        parse_sonarqube_results(content)
