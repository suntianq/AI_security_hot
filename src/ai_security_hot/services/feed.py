"""Cursor-paginated document feed + full-text search for the public frontend.

Both read the same current-document corpus as ``build_overview`` (source_status
``active``, record_status not withdrawn) and reuse its module endpoint universe
and noise filter, ordered by fetch time. Read-only; no schema change.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from ai_security_hot.models.tables import Document, RawItem, Source, SourceEndpoint
from ai_security_hot.services.overview import (
    _MODULE_BY_ENDPOINT,
    MODULES,
    SOURCE_LABELS,
    _clean_summary,
    _is_noise,
)
from ai_security_hot.storage.repositories import current_document_conditions

VALID_MODULES: frozenset[str] = frozenset(m["id"] for m in MODULES)

TECH_LABELS = {
    "llm": "大模型",
    "ai_for_security": "AI 用于安全",
    "security_for_ai": "AI 自身安全",
    "agent": "智能体",
    "system_security": "系统安全",
}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _labels() -> dict[str, dict[str, str]]:
    """Display labels mirrored from the overview payload."""
    return {"source": dict(SOURCE_LABELS), "tech": dict(TECH_LABELS)}


def _resolve_endpoints(module: str | None) -> set[str]:
    """Endpoint ids for a module filter; all module endpoints when None."""
    if module is None:
        return {ep for m in MODULES for ep in m["endpoints"]}
    if module not in VALID_MODULES:
        raise ValueError(f"unknown module: {module}")
    return {ep for m in MODULES if m["id"] == module for ep in m["endpoints"]}


def _source_name_map(session: Session) -> dict[str, str]:
    rows = session.execute(
        select(SourceEndpoint.id, Source.name).join(Source, Source.id == SourceEndpoint.source_id)
    )
    return {row.id: row.name for row in rows}


def _escape_like(value: str) -> str:
    """Escape ILIKE wildcards so user input matches literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _base_conditions(
    *,
    module: str | None,
    source: str | None,
    tech_direction: str | None,
) -> list[Any]:
    """Shared current-document predicates for feed and search."""
    conds = list(current_document_conditions())
    conds.append(Document.endpoint_id.in_(_resolve_endpoints(module)))
    if source:
        conds.append(Document.endpoint_id == source)
    if tech_direction:
        conds.append(Document.tech_directions.contains([tech_direction]))
    return conds


def _serialize(
    doc_id: int,
    title: str,
    body: str | None,
    url: str | None,
    ep: str,
    tech: list[str] | None,
    etype: str | None,
    published_at: datetime | None,
    fetched_at: datetime | None,
    source_name: dict[str, str],
) -> dict[str, Any]:
    return {
        "id": doc_id,
        "document_id": doc_id,
        "title": title,
        "summary": _clean_summary(body, 300),
        "url": url,
        "source": ep,
        "source_name": source_name.get(ep, ep),
        "tech": tech or [],
        "etype": etype,
        "fetched": _iso(fetched_at),
        "published_at": _iso(published_at),
        "module": _MODULE_BY_ENDPOINT.get(ep, "news"),
    }


def build_feed(
    session: Session,
    *,
    limit: int = 50,
    before: datetime | None = None,
    since: datetime | None = None,
    module: str | None = None,
    tech_direction: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    """Return a keyset-paginated feed ordered by fetch time (newest first).

    ``before`` is an exclusive ISO fetched_at cursor; ``since`` is an inclusive
    lower bound for time-range filters. Noise rows are skipped in Python while
    the cursor always advances from the last examined row, so pagination never
    loops.
    """
    if not 0 < limit <= 100:
        raise ValueError("limit must be in 1..100")
    conds = _base_conditions(module=module, source=source, tech_direction=tech_direction)
    if before is not None:
        conds.append(RawItem.fetched_at < before)
    if since is not None:
        conds.append(RawItem.fetched_at >= since)

    rows = session.execute(
        select(
            Document.id,
            Document.title_original,
            Document.body_text,
            Document.canonical_url,
            Document.endpoint_id,
            Document.tech_directions,
            Document.classified_event_type,
            Document.published_at_utc,
            RawItem.fetched_at,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(*conds)
        .order_by(desc(RawItem.fetched_at), desc(Document.id))
        .limit(limit + 1)
    ).all()

    source_name = _source_name_map(session)
    items: list[dict[str, Any]] = []
    next_before: str | None = None
    for (
        doc_id,
        title,
        body,
        url,
        ep,
        tech,
        etype,
        published_at,
        fetched_at,
    ) in rows:
        topic = (tech or [None])[0] if tech else None
        if _is_noise(title, topic):
            continue
        items.append(
            _serialize(
                doc_id, title, body, url, ep, tech, etype, published_at, fetched_at, source_name
            )
        )
    if len(rows) > limit:
        next_before = _iso(rows[-1].fetched_at)

    return {"items": items, "next_before": next_before, "labels": _labels()}


def search_documents(
    session: Session,
    *,
    q: str,
    page: int = 1,
    limit: int = 20,
    module: str | None = None,
    tech_direction: str | None = None,
    source: str | None = None,
    since: datetime | None = None,
) -> dict[str, Any]:
    """Full-text search over current documents (title or body), newest first."""
    if not q or len(q) < 2:
        raise ValueError("q must be at least 2 characters")
    if not 0 < limit <= 100:
        raise ValueError("limit must be in 1..100")
    conds = _base_conditions(module=module, source=source, tech_direction=tech_direction)
    pat = f"%{_escape_like(q)}%"
    conds.append(
        or_(
            Document.title_original.ilike(pat, escape="\\"),
            Document.body_text.ilike(pat, escape="\\"),
        )
    )
    if since is not None:
        conds.append(RawItem.fetched_at >= since)

    total = session.scalar(
        select(func.count())
        .select_from(Document)
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(*conds)
    )
    rows = session.execute(
        select(
            Document.id,
            Document.title_original,
            Document.body_text,
            Document.canonical_url,
            Document.endpoint_id,
            Document.tech_directions,
            Document.classified_event_type,
            Document.published_at_utc,
            RawItem.fetched_at,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(*conds)
        .order_by(Document.published_at_utc.desc().nullslast(), desc(Document.id))
        .offset((page - 1) * limit)
        .limit(limit)
    ).all()

    source_name = _source_name_map(session)
    items = []
    for (
        doc_id,
        title,
        body,
        url,
        ep,
        tech,
        etype,
        published_at,
        fetched_at,
    ) in rows:
        topic = (tech or [None])[0] if tech else None
        if _is_noise(title, topic):
            continue
        items.append(
            _serialize(
                doc_id, title, body, url, ep, tech, etype, published_at, fetched_at, source_name
            )
        )

    return {
        "total": int(total or 0),
        "items": items,
        "page": page,
        "limit": limit,
        "labels": _labels(),
    }
