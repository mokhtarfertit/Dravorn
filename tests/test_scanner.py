from pathlib import Path

from src.scanner.nmap_scanner import parse_nmap_xml


def test_parse_nmap_xml_returns_only_open_services():
    fixture_path = Path("tests/fixtures/nmap_services.xml")
    xml_text = fixture_path.read_text(encoding="utf-8")

    result = parse_nmap_xml(
        xml_text=xml_text,
        target="example.com",
    )

    assert result.target == "example.com"
    assert result.scanner_name == "nmap"
    assert len(result.services) == 2

    ssh_service = result.services[0]
    assert ssh_service.port == 22
    assert ssh_service.name == "ssh"
    assert ssh_service.product == "OpenSSH"
    assert ssh_service.version == "9.6"

    http_service = result.services[1]
    assert http_service.port == 80
    assert http_service.name == "http"
    assert http_service.product == "nginx"
    assert http_service.version == "1.24.0"
    ####