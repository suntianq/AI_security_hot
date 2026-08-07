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
    def __init__(self, token: str | None, admin_token: str | None = None) -> None:
        self.api_token = token
        self.admin_api_token = admin_token
        self.build_sha = "test-build"


def _client(token: str | None, admin_token: str | None = None) -> TestClient:
    import ai_security_hot.api.app as app_mod

    app_mod.get_settings = lambda: _FakeSettings(  # type: ignore[method-assign]
        token, admin_token
    )
    return TestClient(app)


def test_fails_closed_when_token_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(None)
    assert client.get("/stats").status_code == 503
    assert client.post("/ops/classify").status_code == 503


def test_health_is_exempt_from_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(None)
    for path in ("/health", "/health/live"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json()["build_sha"] == "test-build"


def test_requires_bearer_token_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client("secret-token")
    assert client.get("/stats").status_code == 401  # missing header
    assert client.get("/stats", headers={"Authorization": "Bearer wrong-token"}).status_code == 401
    assert client.get("/stats", headers={"Authorization": "not-bearer"}).status_code == 401


def test_ops_routes_require_separate_admin_token(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client("read-token", "admin-token")

    read_header = {"Authorization": "Bearer read-token"}
    admin_header = {"Authorization": "Bearer admin-token"}
    assert client.post("/ops/classify", headers=read_header).status_code == 401
    # Middleware accepts the admin credential. Avoid executing the expensive
    # handler by using a method that has no route (GET vs POST). With the root
    # StaticFiles mount this falls through to a 404 rather than 405, which still
    # proves the admin token passed the middleware without running the handler.
    assert client.get("/ops/classify", headers=admin_header).status_code == 404


@pytest.mark.db
def test_ready_checks_database_and_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    if not os.environ.get("INTEL_DATABASE_URL"):
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    response = _client(None).get("/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["schema_heads"]


@pytest.mark.db
def test_valid_token_reaches_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    if not os.environ.get("INTEL_DATABASE_URL"):
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    client = _client("secret-token")
    ok = client.get("/stats", headers={"Authorization": "Bearer secret-token"})
    assert ok.status_code == 200
    assert "documents" in ok.json()
