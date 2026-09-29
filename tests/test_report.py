from src.models.scan_result import ScanResult, Service
from src.models.vulnerability import (
    FindingStatus,
    Severity,
    VulnerabilityFinding,
)
from src.report.report_generator import generate_markdown_report


def test_report_contains_service_and_finding():
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

    findings = [
        VulnerabilityFinding(
            title="Demo HTTP Server vulnerable version",
            severity=Severity.MEDIUM,
            status=FindingStatus.POTENTIAL,
            confidence="medium",
            evidence="DemoHTTP 1.0.0 detected on 80/tcp.",
            description="Demo advisory used only for testing.",
            remediation="Upgrade DemoHTTP.",
            cve_id="CVE-DEMO-0001",
            cwe_id="CWE-000",
        )
    ]

    report = generate_markdown_report(scan_result, findings)

    assert "# Dravorn Security Assessment Report" in report
    assert "`80/tcp`" in report
    assert "DemoHTTP 1.0.0" in report
    assert "Demo HTTP Server vulnerable version" in report
    assert "MEDIUM" in report
    assert "potential" in report
    assert "Human review is required" in report

def test_save_markdown_report_creates_a_markdown_file(tmp_path):
    from src.report.report_generator import save_markdown_report

    report_path = save_markdown_report(
        report_content="# Test Report\n",
        output_directory=tmp_path,
        target="example.com",
    )

    assert report_path.exists()
    assert report_path.suffix == ".md"
    assert report_path.read_text(encoding="utf-8") == "# Test Report\n"