import json

import pytest

from src.llm.model import LLMClientError, LocalLLMClient
from src.models.scan_result import Service
from src.models.vulnerability import (
    FindingStatus,
    Severity,
    VulnerabilityFinding,
)


def test_client_rejects_non_local_url():
    with pytest.raises(LLMClientError, match="loopback"):
        LocalLLMClient(
            base_url="https://example.com/v1",
            api_key="test-key",
        )


def test_explain_finding_sends_evidence_to_local_server(monkeypatch):
    captured_request = {}

    class FakeResponse:
        def read(self):
            return json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    "Summary: Potential issue detected.\n"
                                    "Risk: Review the affected service.\n"
                                    "Confidence: Medium.\n"
                                    "Remediation: Upgrade the service."
                                )
                            }
                        }
                    ]
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    def fake_urlopen(request, timeout):
        captured_request["url"] = request.full_url
        captured_request["timeout"] = timeout
        captured_request["authorization"] = request.get_header(
            "Authorization"
        )
        captured_request["payload"] = json.loads(
            request.data.decode("utf-8")
        )

        return FakeResponse()

    monkeypatch.setattr(
        "src.llm.model.urlopen",
        fake_urlopen,
    )

    client = LocalLLMClient(
        base_url="http://127.0.0.1:8080/v1",
        api_key="test-local-key",
    )

    service = Service(
        port=80,
        protocol="tcp",
        state="open",
        name="http",
        product="DemoHTTP",
        version="1.0.0",
    )

    finding = VulnerabilityFinding(
        title="Demo HTTP Server vulnerable version",
        severity=Severity.MEDIUM,
        status=FindingStatus.POTENTIAL,
        confidence="medium",
        evidence="DemoHTTP 1.0.0 detected on 80/tcp.",
        remediation="Upgrade DemoHTTP.",
    )

    explanation = client.explain_finding(
        finding=finding,
        service=service,
    )

    assert captured_request["url"] == (
        "http://127.0.0.1:8080/v1/chat/completions"
    )
    assert captured_request["authorization"] == (
        "Bearer test-local-key"
    )
    assert captured_request["payload"]["max_tokens"] == 160
    assert captured_request["payload"]["temperature"] == 0.2
    assert "DemoHTTP" in captured_request["payload"]["messages"][1][
        "content"
    ]
    assert "Summary:" in explanation