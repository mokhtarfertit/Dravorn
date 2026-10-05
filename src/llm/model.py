from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from src.models.scan_result import Service
from src.models.vulnerability import VulnerabilityFinding


class LLMClientError(RuntimeError):
    """Raised when the local LLM server cannot provide a valid response."""


@dataclass
class LocalLLMClient:
    """Client for a llama.cpp server running only on this computer."""

    base_url: str
    api_key: str
    model_name: str = "local-qwen3-4b"
    timeout_seconds: int = 180

    def __post_init__(self) -> None:
        parsed_url = urlparse(self.base_url)

        allowed_hosts = {"127.0.0.1", "localhost", "::1"}

        if (
            parsed_url.scheme != "http"
            or parsed_url.hostname not in allowed_hosts
        ):
            raise LLMClientError(
                "Local LLM URL must use http and a loopback address."
            )

        if not self.api_key:
            raise LLMClientError(
                "DRAVORN_LLM_KEY is required for the local LLM server."
            )

    @classmethod
    def from_environment(cls) -> "LocalLLMClient":
        return cls(
            base_url=os.getenv(
                "DRAVORN_LLM_URL",
                "http://127.0.0.1:8080/v1",
            ),
            api_key=os.getenv("DRAVORN_LLM_KEY", ""),
        )

    def explain_finding(
        self,
        finding: VulnerabilityFinding,
        service: Service,
    ) -> str:
        """Generate a concise explanation for one potential finding."""
        evidence = {
            "service": {
                "port": service.port,
                "protocol": service.protocol,
                "name": service.name,
                "product": service.product,
                "version": service.version,
            },
            "finding": {
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "cve_id": finding.cve_id,
                "cwe_id": finding.cwe_id,
                "evidence": finding.evidence,
                "description": finding.description,
                "remediation": finding.remediation,
            },
        }

        system_prompt = (
            "You are Dravorn's local security-report assistant. "
            "Use only the supplied evidence. "
            "A finding with status 'potential' is not confirmed. "
            "Do not provide exploitation steps, scan commands, or attack "
            "instructions. Return concise report text with these headings: "
            "Summary, Risk, Confidence, Remediation."
        )

        user_prompt = (
            "Analyze this evidence for a defensive security report:\n\n"
            f"{json.dumps(evidence, indent=2)}"
        )

        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            "temperature": 0.2,
            "max_tokens": 160,
            "stream": False,
        }

        request = Request(
            url=f"{self.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_data = json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as error:
            raise LLMClientError(
                f"Local LLM server returned HTTP {error.code}."
            ) from error
        except URLError as error:
            raise LLMClientError(
                "Could not connect to the local LLM server."
            ) from error
        except TimeoutError as error:
            raise LLMClientError(
                "Local LLM server took too long to respond."
            ) from error
        except json.JSONDecodeError as error:
            raise LLMClientError(
                "Local LLM server returned invalid JSON."
            ) from error

        try:
            content = response_data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise LLMClientError(
                "Local LLM response did not contain generated text."
            ) from error

        if not isinstance(content, str) or not content.strip():
            raise LLMClientError(
                "Local LLM response was empty."
            )

        return content.strip()