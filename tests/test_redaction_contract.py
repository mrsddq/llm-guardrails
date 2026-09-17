import json

import pytest
from fastapi.testclient import TestClient

from llm_guardrails import GuardrailEngine
from llm_guardrails.api import app


@pytest.mark.parametrize("secret", ["user@example.com", "sk_1234567890abcdefghijkl", "4111 1111 1111 1111"])
def test_redacted_serialization_contains_no_original_secret(secret):
    result = GuardrailEngine().scan_output(f"Sensitive value: {secret}")
    assert secret not in json.dumps(result.to_dict())


def test_overlapping_email_canary_does_not_leave_secret_fragments():
    canary = "PRIVATE-user@example.com-CANARY"
    result = GuardrailEngine().scan_output(f"First {canary}, again {canary}", canary=canary)
    serialized = json.dumps(result.to_dict())
    assert "PRIVATE" not in serialized
    assert "example.com" not in serialized
    assert len([d for d in result.detections if d.rule == "GRD104"]) == 2
    assert result.action == "block"


def test_normalized_canary_is_detected():
    result = GuardrailEngine().scan_output("secret ABC", canary="ＡＢＣ")
    assert result.action == "block"
    assert "ABC" not in result.sanitized_text


def test_explicit_no_redact_preserves_text():
    result = GuardrailEngine().scan_output("user@example.com", redact=False)
    assert result.normalized_text == result.sanitized_text == "user@example.com"


def test_overbudget_input_fails_closed():
    result = GuardrailEngine(max_chars=10).scan_input("a" * 11)
    assert result.action == "block"
    assert len(result.normalized_text) == 10


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_budget_rejected(limit):
    with pytest.raises(ValueError):
        GuardrailEngine(max_chars=limit)


def test_api_does_not_echo_redacted_values():
    client = TestClient(app)
    response = client.post("/v1/scan/output", json={"text": "user@example.com"})
    assert response.status_code == 200
    assert "user@example.com" not in response.text
    assert client.post("/v1/scan/input", json={"text": "x" * 20_001}).status_code == 422


def test_api_handles_unicode_expansion_over_budget():
    response = TestClient(app).post("/v1/scan/output", json={"text": "ﬃ" * 10_000})
    assert response.status_code == 422


@pytest.mark.parametrize("payload", [
    {"text": "private-person@example.com" + "x" * 20_001},
    {"text": "private-person@example.com", "redact": "secret-invalid-boolean"},
    {"text": "private-person@example.com", "canary": "private-canary" * 30},
])
def test_validation_errors_do_not_echo_sensitive_request_fields(payload):
    response = TestClient(app).post("/v1/scan/output", json=payload)
    assert response.status_code == 422
    assert "private-person" not in response.text
    assert "private-canary" not in response.text
    assert "secret-invalid" not in response.text
    assert all("input" not in item and "ctx" not in item for item in response.json()["detail"])
