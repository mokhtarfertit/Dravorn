from __future__ import annotations

import xml.etree.ElementTree as element_tree

from src.models.scan_result import ScanResult, Service


class NmapParseError(ValueError):
    """Raised when Nmap XML output cannot be parsed."""


def parse_nmap_xml(xml_text: str, target: str) -> ScanResult:
    """
    Convert Nmap XML output into Dravorn's internal scan-result model.

    Only open ports are included. No command is executed here.
    """
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