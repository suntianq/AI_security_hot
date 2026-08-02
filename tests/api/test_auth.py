"""API bearer-token auth tests.

Fail-closed behavior is DB-free (the middleware short-circuits before the
handler). The success path exercises a real route and needs a migrated
``INTEL_DATABASE_URL``, matching the other PostgreSQL integration tests.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from ai_security_hot.api.app import app


class _FakeSettings:
    def __init__(self, token: str | None) -> None:
        self.api_token = token


def _client(token: str | None) -> TestClient:
    import ai_security_hot.api.app as app_mod

    app_mod.get_settings = lambda: _FakeSettings(token)  # type: ignore[method-assign]
    return TestClient(app)


def test_fails_closed_when_token_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(None)
    assert client.get("/stats").status_code == 503
    assert client.post("/ops/tick").status_code == 503


def test_health_is_exempt_from_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    # /health must stay open for load-balancer liveness probes.
    client = _client(None)
    assert client.get("/health").status_code == 200


def test_requires_bearer_token_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client("secret-token")
    assert client.get("/stats").status_code == 401  # missing header
    assert client.get("/stats", headers={"Authorization": "Bearer wrong-token"}).status_code == 401
    assert client.get("/stats", headers={"Authorization": "not-bearer"}).status_code == 401


@pytest.mark.db
def test_valid_token_reaches_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    if not os.environ.get("INTEL_DATABASE_URL"):
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    client = _client("secret-token")
    ok = client.get("/stats", headers={"Authorization": "Bearer secret-token"})
    assert ok.status_code == 200
    assert "documents" in ok.json()
