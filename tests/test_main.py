import sys

from src import main as dravorn_main
from src.models.scan_result import ScanResult, Service
from src.models.vulnerability import (
    FindingStatus,
    Severity,
    VulnerabilityFinding,
)
from src.utils.target_validator import AuthorizedTarget, TargetKind


def test_main_adds_ai_explanation_to_a_finding(monkeypatch):
    service = Service(
        port=80,
        protocol="tcp",
        state="open",
        name="http",
        product="DemoHTTP",
        version="1.0.0",
    )

    scan_result = ScanResult(target="example.com")
    scan_result.add_service(service)

    finding = VulnerabilityFinding(
        title="DemoHTTP 1.0.0 requires security review",
        severity=Severity.MEDIUM,
        status=FindingStatus.POTENTIAL,
        confidence="medium",
        evidence="DemoHTTP 1.0.0 detected on 80/tcp.",
        remediation="Upgrade DemoHTTP.",
        service_port=80,
        service_protocol="tcp",
    )

    def fake_validate_target(raw_target, authorized):
        return AuthorizedTarget(
            value="example.com",
            kind=TargetKind.DOMAIN,
        )

    def fake_run_nmap_scan(target):
        return scan_result

    def fake_analyze_scan(scan_result, advisory_path):
        return [finding]

    class FakeLLMClient:
        @classmethod
        def from_environment(cls):
            return cls()

        def explain_finding(self, finding, service):
            assert service.product == "DemoHTTP"
            assert service.version == "1.0.0"

            return "Fake AI explanation for the test."
    def fake_generate_markdown_report(scan_result, findings):
        assert scan_result.target == "example.com"
        assert findings[0].ai_explanation == "Fake AI explanation for the test."

        return "# Fake Dravorn report"


    def fake_save_markdown_report(report_content, output_directory, target):
        assert report_content == "# Fake Dravorn report"
        assert target == "example.com"

        return output_directory / "report_example.com_test.md"
    monkeypatch.setattr(
        dravorn_main,
        "validate_target",
        fake_validate_target,
    )
    monkeypatch.setattr(
        dravorn_main,
        "run_nmap_scan",
        fake_run_nmap_scan,
    )
    monkeypatch.setattr(
        dravorn_main,
        "analyze_scan",
        fake_analyze_scan,
    )
    monkeypatch.setattr(
        dravorn_main,
        "LocalLLMClient",
        FakeLLMClient,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["dravorn", "example.com", "--authorized", "--scan"],
    )

    monkeypatch.setattr(
        dravorn_main,
        "generate_markdown_report",
        fake_generate_markdown_report,
    )
    monkeypatch.setattr(
        dravorn_main,
        "save_markdown_report",
        fake_save_markdown_report,
    )

    result = dravorn_main.main()

    assert result == 0
    assert finding.ai_explanation == "Fake AI explanation for the test."

