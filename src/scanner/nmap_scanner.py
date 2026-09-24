from __future__ import annotations

import socket
import subprocess
import xml.etree.ElementTree as element_tree

from src.models.scan_result import ScanResult, Service
from src.utils.target_validator import (
    AuthorizedTarget,
    TargetKind,
    TargetValidationError,
    validate_resolved_address,
)


class NmapParseError(ValueError):
    """Raised when Nmap XML output cannot be parsed."""


class NmapExecutionError(RuntimeError):
    """Raised when Nmap cannot run or returns an error."""

# this function just reads Nmap XML already produced
def parse_nmap_xml(xml_text: str, target: str) -> ScanResult:
    """Convert Nmap XML output into Dravorn's scan-result model."""
    try:
        root = element_tree.fromstring(xml_text)
    except element_tree.ParseError as error:
        raise NmapParseError("Invalid Nmap XML output.") from error

    result = ScanResult(
        target=target,
        scanner_name="nmap",
    )

    host = root.find("./host")
    if host is None:
        return result

    host_status = host.find("./status")
    if host_status is None or host_status.get("state") != "up":
        return result

    for port_element in host.findall("./ports/port"):
        state_element = port_element.find("./state")

        if state_element is None or state_element.get("state") != "open":
            continue

        service_element = port_element.find("./service")

        service = Service(
            port=int(port_element.get("portid", "0")),
            protocol=port_element.get("protocol", "tcp"),
            state="open",
            name=(
                service_element.get("name", "unknown")
                if service_element is not None
                else "unknown"
            ),
            product=(
                service_element.get("product")
                if service_element is not None
                else None
            ),
            version=(
                service_element.get("version")
                if service_element is not None
                else None
            ),
        )

        result.add_service(service)

    return result


def resolve_authorized_target(target: AuthorizedTarget) -> str:
    """
    Resolve a domain safely.

    The MVP accepts a domain only when it resolves to exactly one public IP.
    This avoids scanning several hosts unexpectedly.
    """
    if target.kind == TargetKind.IP_ADDRESS:
        validate_resolved_address(target.value)
        return target.value

    try:
        address_info = socket.getaddrinfo(
            target.value,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise NmapExecutionError(
            f"Could not resolve domain '{target.value}'."
        ) from error

    addresses = {item[4][0] for item in address_info}

    if not addresses:
        raise NmapExecutionError(
            f"No IP address was found for '{target.value}'."
        )

    for address in addresses:
        try:
            validate_resolved_address(address)
        except TargetValidationError as error:
            raise NmapExecutionError(
                f"Domain '{target.value}' resolves to a disallowed address."
            ) from error

    if len(addresses) != 1:
        raise NmapExecutionError(
            "This domain resolves to multiple IP addresses. "
            "For this MVP, use one explicitly authorized public IP address."
        )

    return addresses.pop()


def run_nmap_scan(
    target: AuthorizedTarget,
    timeout_seconds: int = 300,
) -> ScanResult:
    """
    Run a limited Nmap service/version discovery scan.

    No NSE scripts, brute force, exploit checks, or OS detection are used.
    """
    resolved_address = resolve_authorized_target(target)

    command = [
        "nmap",
        "-sV",
        "--version-light",
        "-T3",
        "--host-timeout",
        "2m",
        "-oX",
        "-",
        "--",
        resolved_address,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as error:
        raise NmapExecutionError(
            "Nmap was not found. Install Nmap and make sure it is in PATH."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise NmapExecutionError(
            "Nmap scan exceeded the allowed time limit."
        ) from error

    if completed.returncode != 0:
        message = completed.stderr.strip() or "Unknown Nmap error."
        raise NmapExecutionError(f"Nmap failed: {message}")

    return parse_nmap_xml(
        xml_text=completed.stdout,
        target=target.value,
    )