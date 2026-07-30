"""Load and validate sources.yaml into typed Source Policy objects.

Site-specific behaviour lives in YAML, not in scheduler code (MVP 5.3).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from ai_security_hot.config.settings import get_settings
from ai_security_hot.domain.enums import ConnectorKind, EgressRoute, Priority, TrustTier


class SchedulePolicy(BaseModel):
    interval_minutes: int = Field(default=60, ge=1)
    jitter_seconds: int = Field(default=60, ge=0)


class FetchPolicy(BaseModel):
    timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    max_response_bytes: int = Field(default=5 * 1024 * 1024, ge=1)
    max_redirects: int = Field(default=3, ge=0, le=20)
    requests_per_minute: float = Field(default=2.0, ge=0)


class EgressPolicy(BaseModel):
    route: EgressRoute = EgressRoute.DIRECT


class EndpointPolicy(BaseModel):
    """One source_endpoint's full configuration (MVP 5.3)."""

    id: str
    source_id: str
    connector: ConnectorKind
    parser: str | None = None
    url: str
    enabled: bool = True
    # Bump when checkpoint semantics change (cursor meaning, bootstrap window,
    # connector protocol). Registry sync resets only this endpoint's state.
    state_version: str = "1"
    trust_tier: TrustTier = TrustTier.B
    priority: Priority = Priority.P1
    language: str | None = None
    egress: EgressPolicy = Field(default_factory=EgressPolicy)
    schedule: SchedulePolicy = Field(default_factory=SchedulePolicy)
    fetch: FetchPolicy = Field(default_factory=FetchPolicy)
    topics: list[str] = Field(default_factory=list)
    # second-fetch full text from the article URL when the feed only gives a
    # summary AND the page is static HTML (SPA pages need Playwright — leave off)
    fulltext: bool = False
    # optional per-connector options, e.g. rest: {list_key, id_field, nested_key}
    options: dict = Field(default_factory=dict)

    @field_validator("state_version")
    @classmethod
    def _state_version_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("state_version must not be empty")
        return v

    @field_validator("url")
    @classmethod
    def _url_must_be_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError(f"endpoint url must be http(s): {v!r}")
        return v


class SourceDef(BaseModel):
    id: str
    name: str
    trust_tier: TrustTier = TrustTier.B
    language: str | None = None
    org: str | None = None


class SourceRegistry(BaseModel):
    sources: list[SourceDef]
    endpoints: list[EndpointPolicy]

    @model_validator(mode="after")
    def _validate_registry(self) -> SourceRegistry:
        source_ids = [source.id for source in self.sources]
        endpoint_ids = [endpoint.id for endpoint in self.endpoints]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("duplicate source ids")
        if len(endpoint_ids) != len(set(endpoint_ids)):
            raise ValueError("duplicate endpoint ids")
        known_sources = set(source_ids)
        for endpoint in self.endpoints:
            if endpoint.source_id not in known_sources:
                raise ValueError(
                    f"endpoint {endpoint.id!r} references unknown source {endpoint.source_id!r}"
                )
            if endpoint.connector is ConnectorKind.AIHOT:
                changes_url = (endpoint.options.get("aihot") or {}).get("changes_url")
                if not isinstance(changes_url, str) or not changes_url.startswith(
                    ("http://", "https://")
                ):
                    raise ValueError(f"AI HOT endpoint {endpoint.id!r} requires changes_url")
        return self

    def endpoint(self, endpoint_id: str) -> EndpointPolicy:
        for e in self.endpoints:
            if e.id == endpoint_id:
                return e
        raise KeyError(f"unknown endpoint: {endpoint_id}")


def load_registry(path: str | Path | None = None) -> SourceRegistry:
    """Parse sources.yaml, validating every endpoint's schema."""
    if path is None:
        path = get_settings().sources_file
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    registry = SourceRegistry.model_validate(data)

    known_sources = {s.id for s in registry.sources}
    for ep in registry.endpoints:
        if ep.source_id not in known_sources:
            raise ValueError(f"endpoint {ep.id!r} references unknown source {ep.source_id!r}")
    return registry
