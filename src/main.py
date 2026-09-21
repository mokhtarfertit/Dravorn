from __future__ import annotations

import argparse

from src.utils.target_validator import TargetValidationError, validate_target


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
    print("No scan has been started.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())