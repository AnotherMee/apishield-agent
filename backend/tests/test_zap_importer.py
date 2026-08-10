import json

import pytest

from app.tools.zap_importer import import_zap_results, parse_zap_results


ZAP_REPORT = {
    "@version": "2.15.0",
    "site": [
        {
            "@name": "https://api.example.test",
            "alerts": [
                {
                    "pluginid": "10020",
                    "alert": "Missing Anti-clickjacking Header",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "<p>A response header was missing.</p>",
                    "solution": "<p>Return an appropriate defensive header.</p>",
                    "instances": [
                        {
                            "uri": "https://api.example.test/users/42?expand=profile",
                            "method": "get",
                            "param": "expand",
                            "evidence": "header absent",
                        }
                    ],
                },
                {
                    "pluginid": "90001",
                    "alert": "Informational observation",
                    "riskdesc": "Informational (Low)",
                    "confidence": "Low",
                    "instances": [],
                },
            ],
        }
    ],
}


def test_parse_zap_results_normalizes_alerts() -> None:
    findings = parse_zap_results(json.dumps(ZAP_REPORT))

    assert len(findings) == 2
    finding = findings[0]
    assert finding == {
        "id": "ZAP-10020-001",
        "method": "GET",
        "endpoint": "/users/42?expand=profile",
        "category": "missing-anti-clickjacking-header",
        "severity": "medium",
        "confidence": 0.85,
        "evidence": [
            "A response header was missing.",
            "Parameter: expand",
            "Observed evidence: header absent",
        ],
        "source_tools": ["owasp-zap-import"],
        "remediation": "Return an appropriate defensive header.",
        "status": "imported-needs-review",
    }
    assert findings[1]["endpoint"] == "/"
    assert findings[1]["severity"] == "info"


def test_import_zap_results_reads_a_file(tmp_path) -> None:
    report = tmp_path / "zap-report.json"
    report.write_text(json.dumps(ZAP_REPORT), encoding="utf-8")
    assert len(import_zap_results(report)) == 2


@pytest.mark.parametrize("content", [b"not-json", b"{}", b"[]"])
def test_parse_zap_results_rejects_invalid_reports(content: bytes) -> None:
    with pytest.raises(ValueError, match="ZAP"):
        parse_zap_results(content)
