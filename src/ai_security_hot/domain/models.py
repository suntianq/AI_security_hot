"""Domain value objects that flow through the pipeline.

These are Pydantic models decoupled from the SQLAlchemy ORM tables in
``models/``. Connectors and parsers speak these types; repositories map
them to/from rows.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from pydantic import BaseModel, Field

from .enums import ConnectorKind, EgressRoute


def content_sha256(*parts: str | bytes) -> str:
    """Stable SHA-256 over the given parts — used for hard dedup and blobs."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8") if isinstance(p, str) else p)
    return h.hexdigest()


class FetchResult(BaseModel):
    """Raw controlled HTTP response returned by FetchContext."""

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes
    fetched_at: datetime
    egress_route: EgressRoute
    from_cache: bool = False  # 304 Not Modified served from checkpoint

    @property
    def etag(self) -> str | None:
        return self.headers.get("etag")

    @property
    def last_modified(self) -> str | None:
        return self.headers.get("last-modified")


class RawItem(BaseModel):
    """Immutable raw evidence (MVP 6.2). Corrections happen via new versions."""

    endpoint_id: str
    source_id: str
    native_id: str  # source-native id — first idempotency key
    request_url: str
    final_url: str
    http_status: int
    published_at: datetime | None = None
    fetched_at: datetime
    language: str | None = None
    content_hash: str  # SHA-256 of raw content
    blob_ref: str | None = None  # BlobStore reference for large snapshots (plan 修正 5)
    connector_kind: ConnectorKind
    connector_version: str
    parser_version: str | None = None
    raw_text: str | None = None  # small inline payload; large snapshots go to blob_ref
    canonical_url: str | None = None


class NormalizedDocument(BaseModel):
    """Standardized document (MVP 6.3)."""

    raw_item_native_id: str
    endpoint_id: str
    title_original: str
    title_zh: str | None = None
    body_text: str | None = None
    canonical_url: str
    author: str | None = None
    org: str | None = None
    published_at: datetime | None = None
    published_at_utc: datetime | None = None
    language: str | None = None
    # structured identifiers extracted from the text
    cve_ids: list[str] = Field(default_factory=list)
    ghsa_ids: list[str] = Field(default_factory=list)
    cnvd_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)  # companies/models/repos/...
    raw_metadata: dict[str, str] = Field(default_factory=dict)
    # parse quality (plan 修正 4): did the parse hit the source's minimum bar?
    parse_quality: float = 0.0


class SourceHealth(BaseModel):
    """Per-endpoint health snapshot (MVP 16.2 / system-design 17.2)."""

    endpoint_id: str
    status: str
    last_success_at: datetime | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
