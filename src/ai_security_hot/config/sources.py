"""Load and validate sources.yaml into typed Source Policy objects.

Site-specific behaviour lives in YAML, not in scheduler code (MVP 5.3).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from ai_security_hot.config.settings import get_settings
from ai_security_hot.domain.enums import ConnectorKind, EgressRoute, Priority, TrustTier


class SchedulePolicy(BaseModel):
    interval_minutes: int = 60
    jitter_seconds: int = 60


class FetchPolicy(BaseModel):
    timeout_seconds: float = 20.0
    max_response_bytes: int = 5 * 1024 * 1024
    max_redirects: int = 3
    requests_per_minute: float = 2.0


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
