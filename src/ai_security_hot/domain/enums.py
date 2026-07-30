"""Domain enums — shared vocabulary across connectors, pipelines and models."""

from __future__ import annotations

from enum import StrEnum


class Topic(StrEnum):
    """The four top-level content lines (MVP 2.1)."""

    AI = "ai"
    AI_FOR_SECURITY = "ai_for_security"
    AI_ENABLED_THREATS = "ai_enabled_threats"
    SECURITY_FOR_AI = "security_for_ai"


class TrustTier(StrEnum):
    """Source trust tier (source-registry §1)."""

    A = "A"  # first-party / authoritative
    B = "B"  # professional research / analysis
    C = "C"  # media / community / discovery-only


class Priority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class ConnectorKind(StrEnum):
    RSS = "rss"
    REST = "rest"
    NVD = "nvd"  # modified-time windows + durable segmented catch-up cursor
    AIHOT = "aihot"  # selected snapshot + durable changes ledger
    GITHUB = "github"
    WEB = "web"
    ARXIV = "arxiv"  # official arXiv API (Atom response) — API-tier
    SITEMAP = "sitemap"  # sitemap.xml discovery + per-article trafilatura
    PLAYWRIGHT = "playwright"  # reserved, profile-gated


class EgressRoute(StrEnum):
    """Where a fetch exits the network (plan 修正 3)."""

    DIRECT = "direct"
    PROXY_POOL_CN = "proxy_pool_cn"
    PROXY_POOL_GLOBAL = "proxy_pool_global"


class PipelineStage(StrEnum):
    """Stage state machine for a raw item (plan 修正 1).

    Each stage is claimed independently and idempotently so a slow LLM
    enrich stage never blocks fast fetch.
    """

    FETCHED = "fetched"
    NORMALIZED = "normalized"
    DEDUPED = "deduped"
    CLUSTERED = "clustered"
    ENRICHED = "enriched"
    DONE = "done"
    FAILED = "failed"


class SourceRecordStatus(StrEnum):
    ACTIVE = "active"
    WITHDRAWN = "withdrawn"
    RETIRED = "retired"


class DocumentSourceStatus(StrEnum):
    """Lifecycle of a local document revision/evidence membership."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"
    RETIRED = "retired"


class UpstreamRecordStatus(StrEnum):
    """Normalized semantic status asserted by the upstream publisher."""

    PUBLISHED = "published"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    UNKNOWN = "unknown"


NON_CURRENT_UPSTREAM_STATUSES = frozenset(
    {UpstreamRecordStatus.REJECTED.value, UpstreamRecordStatus.WITHDRAWN.value}
)


class SourceStatus(StrEnum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    PAUSED = "paused"
    RETIRED = "retired"


class DeliveryChannel(StrEnum):
    EMAIL = "email"
    FEISHU = "feishu"
