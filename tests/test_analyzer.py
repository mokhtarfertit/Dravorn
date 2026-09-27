import json
from pathlib import Path

from src.analyzer.vulnerability_analyzer import analyze_scan
from src.models.scan_result import ScanResult, Service


def test_analyzer_creates_potential_finding_for_exact_match(tmp_path: Path):
    advisory_file = tmp_path / "advisories.json"

    advisory_file.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "title": "Demo HTTP Server vulnerable version",
                        "product": "DemoHTTP",
                        "affected_versions": ["1.0.0"],
                        "severity": "medium",
                        "cve_id": "CVE-DEMO-0001",
                        "cwe_id": "CWE-000",
                        "description": "Demo advisory used only for testing.",
                        "remediation": "Upgrade DemoHTTP to a supported version."
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    scan_result = ScanResult(target="authorized-example.test")
    scan_result.add_service(
        Service(
            port=80,
            protocol="tcp",
            state="open",
            name="http",
            product="DemoHTTP",
            version="1.0.0",
        )
    )

    findings = analyze_scan(
        scan_result=scan_result,
        advisory_path=advisory_file,
    )

    assert len(findings) == 1
    assert findings[0].status.value == "potential"
    assert findings[0].severity.value == "medium"
    assert findings[0].cve_id == "CVE-DEMO-0001"