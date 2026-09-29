from __future__ import annotations

from src.models.scan_result import ScanResult
from src.models.vulnerability import VulnerabilityFinding


def generate_markdown_report(
    scan_result: ScanResult,
    findings: list[VulnerabilityFinding],
) -> str:
    """Create a Markdown report from scan evidence and analysis findings."""
    lines = [
        "# Dravorn Security Assessment Report",
        "",
        "## Scan Information",
        "",
        f"- **Target:** {scan_result.target}",
        f"- **Scanner:** {scan_result.scanner_name}",
        f"- **Scan time:** {scan_result.scanned_at.isoformat()}",
        "",
        "## Discovered Services",
        "",
    ]

    if not scan_result.services:
        lines.append("No open services were discovered.")
    else:
        for service in scan_result.services:
            product = service.product or "Unknown product"
            version = service.version or "Unknown version"

            lines.append(
                f"- `{service.port}/{service.protocol}` — "
                f"**{service.name}**: {product} {version}"
            )

    lines.extend(
        [
            "",
            "## Potential Findings",
            "",
        ]
    )

    if not findings:
        lines.append(
            "No local advisory matched the detected product versions."
        )
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- **Severity:** {finding.severity.value.upper()}",
                    f"- **Status:** {finding.status.value}",
                    f"- **Confidence:** {finding.confidence}",
                    f"- **CVE:** {finding.cve_id or 'Not available'}",
                    f"- **CWE:** {finding.cwe_id or 'Not available'}",
                    f"- **Evidence:** {finding.evidence}",
                    "",
                    "#### Description",
                    "",
                    finding.description or "No description available.",
                    "",
                    "#### Remediation",
                    "",
                    finding.remediation,
                    "",
                ]
            )

    lines.extend(
        [
            "## Important Notice",
            "",
            (
                "This report contains automated, evidence-based potential "
                "findings. A potential finding is not confirmation of a "
                "vulnerability. Human review is required before remediation "
                "or further security testing."
            ),
            "",
        ]
    )

    return "\n".join(lines)