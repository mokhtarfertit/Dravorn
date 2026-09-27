from __future__ import annotations

import argparse
from pathlib import Path

from src.analyzer.vulnerability_analyzer import analyze_scan
from src.scanner.nmap_scanner import NmapExecutionError, run_nmap_scan
from src.utils.target_validator import TargetValidationError, validate_target


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ADVISORY_PATH = PROJECT_ROOT / "data" / "knowledge" / "advisories.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dravorn",
        description="AI-assisted vulnerability analysis tool.",
    )

    parser.add_argument(
        "target",
        help="Public IP address or domain to validate.",
    )

    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you are authorized to assess this target.",
    )

    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run the limited Nmap service/version scan after validation.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        target = validate_target(
            raw_target=args.target,
            authorized=args.authorized,
        )
    except TargetValidationError as error:
        parser.error(str(error))
        return 2

    print("Target accepted.")
    print(f"Target: {target.value}")
    print(f"Type: {target.kind.value}")

    if not args.scan:
        print("No scan has been started.")
        return 0

    try:
        scan_result = run_nmap_scan(target)
    except NmapExecutionError as error:
        parser.error(str(error))
        return 2

    print(f"\nScan finished. Open services: {len(scan_result.services)}")

    for service in scan_result.services:
        product = service.product or "unknown product"
        version = service.version or "unknown version"

        print(
            f"- {service.port}/{service.protocol} "
            f"{service.name} — {product} {version}"
        )

    try:
        findings = analyze_scan(
            scan_result=scan_result,
            advisory_path=ADVISORY_PATH,
        )
    except (OSError, ValueError, KeyError, AttributeError) as error:
        parser.error(f"Could not analyze scan results: {error}")
        return 2

    print(f"\nPotential findings: {len(findings)}")

    if not findings:
        print("No local advisory matched the detected product versions.")
        return 0

    for finding in findings:
        print(f"\n[{finding.severity.value.upper()}] {finding.title}")
        print(f"Status: {finding.status.value}")
        print(f"Evidence: {finding.evidence}")
        print(f"Remediation: {finding.remediation}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())