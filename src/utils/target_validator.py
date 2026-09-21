from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class TargetValidationError(ValueError):
    """Raised when a target is not safe or valid for scanning."""


class TargetKind(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"


@dataclass(frozen=True)
class AuthorizedTarget:
    value: str
    kind: TargetKind


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$",
    re.IGNORECASE,
)

BLOCKED_DOMAIN_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
)


def validate_target(raw_target: str, authorized: bool) -> AuthorizedTarget:
    """
    Validate a user-supplied target before a scan is allowed.

    This validates syntax only. When a domain is resolved later, every
    resolved IP address must also pass validate_resolved_address().
    """
    if not authorized:
        raise TargetValidationError(
            "Scanning requires explicit authorization from the user."
        )

    target = raw_target.strip().rstrip(".")

    if not target:
        raise TargetValidationError("Target cannot be empty.")

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None

    if address is not None:
        validate_resolved_address(str(address))
        return AuthorizedTarget(
            value=str(address),
            kind=TargetKind.IP_ADDRESS,
        )
    

    normalized_domain = target.lower()

    if not DOMAIN_PATTERN.fullmatch(normalized_domain):
        raise TargetValidationError(
            "Target must be a valid public IP address or domain name."
        )

    if normalized_domain == "localhost" or normalized_domain.endswith(
        BLOCKED_DOMAIN_SUFFIXES
    ):
        raise TargetValidationError(
            "Local and internal domain names are not allowed."
        )

    return AuthorizedTarget(
        value=normalized_domain,
        kind=TargetKind.DOMAIN,
    )


def validate_resolved_address(address: str) -> None:
    """
    Reject IP addresses that point to local, private, reserved, or otherwise
    non-public networks.
    """
    parsed_address = ipaddress.ip_address(address)

    if not parsed_address.is_global:
        raise TargetValidationError(
            f"Non-public address '{address}' is not allowed."
        )