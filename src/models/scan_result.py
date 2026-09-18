from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Service:
    """One network service discovered on a target."""

    port: int
    protocol: str
    state: str
    name: str
    product: str | None = None
    version: str | None = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "name": self.name,
            "product": self.product,
            "version": self.version,
        }


@dataclass
class ScanResult:
    """The normalized result of one security scan."""

    target: str
    scanned_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    services: list[Service] = field(default_factory=list)
    scanner_name: str = "nmap"

    def add_service(self, service: Service) -> None:
        self.services.append(service)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at.isoformat(),
            "scanner_name": self.scanner_name,
            "services": [service.to_dict() for service in self.services],
        }