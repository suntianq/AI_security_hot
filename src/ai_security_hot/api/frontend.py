"""Public frontend aggregation API — no bearer token required.

These endpoints feed the public static pages (index.html / event.html /
document.html / daily.html). They only read derived/current data; all
mutations live under /ops/. Detail endpoints return only the fields the
frontend needs (no internal classify_error / raw state).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, Event, EventDocument, Source, SourceEndpoint
from ai_security_hot.services.daily_archive import get_archive, list_archive_dates
from ai_security_hot.services.feed import VALID_MODULES, build_feed, search_documents
from ai_security_hot.services.overview import _clean_summary, build_overview

router = APIRouter(prefix="/api", tags=["frontend"])


@router.get("/overview")
def overview(
    date_str: str | None = Query(None, alias="date", description="natural day YYYY-MM-DD"),
    hot_top_n: int = Query(10, ge=1, le=50),
    per_module_max: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    """Frontend home payload: hotspots + module timelines for a natural day."""
    natural_date: date | None = None
    if date_str:
        try:
            natural_date = date.fromisoformat(date_str)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="date must be YYYY-MM-DD") from exc
    with session_scope() as session:
        return build_overview(
            session,
            hot_top_n=hot_top_n,
            per_module_max=per_module_max,
            natural_date=natural_date,
        )


@router.get("/document/{document_id}")
def public_document(document_id: int) -> dict:
    """Frontend-safe document detail (title, body, source, tags, original url)."""
    with session_scope() as session:
        d = session.get(Document, document_id)
        if d is None:
            raise HTTPException(status_code=404, detail="document not found")
        source_name = d.endpoint_id
        ep = session.execute(
            select(Source.name)
            .select_from(SourceEndpoint)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .where(SourceEndpoint.id == d.endpoint_id)
        ).scalar_one_or_none()
        if ep:
            source_name = str(ep)
        return {
            "id": d.id,
            "title": d.title_original,
            "body": d.body_text,
            "summary": _clean_summary(d.body_text, 300),
            "url": d.canonical_url,
            "source": d.endpoint_id,
            "source_name": source_name,
            "published_at": d.published_at_utc.isoformat() if d.published_at_utc else None,
            "tech_directions": d.tech_directions or [],
            "company_models": d.company_models or [],
            "event_type": d.classified_event_type,
        }


@router.get("/event/{event_id}")
def public_event(event_id: int) -> dict:
    """Frontend-safe event detail + evidence documents (timeline-ordered)."""
    with session_scope() as session:
        event = session.get(Event, event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        rows = session.execute(
            select(EventDocument, Document, Source.name)
            .join(Document, Document.id == EventDocument.document_id)
            .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .where(EventDocument.event_id == event_id)
            .order_by(Document.published_at_utc.nullslast(), Document.published_at_utc, Document.id)
        ).all()
        evidence = [
            {
                "document_id": doc.id,
                "title": doc.title_original,
                "url": doc.canonical_url,
                "source_name": source_name,
                "published_at": (
                    doc.published_at_utc.isoformat() if doc.published_at_utc else None
                ),
                "stance": link.stance,
                "evidence_level": link.evidence_level,
                "relation_reason": link.relation_reason,
            }
            for link, doc, source_name in rows
        ]
        return {
            "id": event.id,
            "title": event.title,
            "summary": event.summary,
            "topic": event.topic,
            "category": event.category,
            "event_type": event.event_type,
            "score": event.score,
            "first_seen_at": event.first_seen_at.isoformat() if event.first_seen_at else None,
            "last_seen_at": event.last_seen_at.isoformat() if event.last_seen_at else None,
            "evidence": evidence,
        }


def _parse_dt(value: str | None) -> datetime | None:
    """Parse an optional ISO-8601 datetime query param, 422 on garbage."""
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid ISO-8601 datetime") from exc


@router.get("/feed")
def feed(
    limit: int = Query(50, ge=1, le=100),
    before: str | None = Query(None, description="ISO-8601 fetched_at cursor, exclusive"),
    since: str | None = Query(None, description="ISO-8601 lower bound (time-range filter)"),
    module: str | None = Query(None),
    tech_direction: str | None = Query(None),
    source: str | None = Query(None, description="endpoint id"),
) -> dict[str, Any]:
    """Cursor-paginated document feed for infinite scroll / cross-day browsing."""
    if module and module not in VALID_MODULES:
        raise HTTPException(status_code=422, detail="unknown module")
    with session_scope() as session:
        return build_feed(
            session,
            limit=limit,
            before=_parse_dt(before),
            since=_parse_dt(since),
            module=module,
            tech_direction=tech_direction,
            source=source,
        )


@router.get("/search")
def search(
    q: str = Query(..., min_length=2, max_length=200),
    module: str | None = Query(None),
    tech_direction: str | None = Query(None),
    source: str | None = Query(None, description="endpoint id"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Full-text search over current documents (title or body), newest first."""
    if module and module not in VALID_MODULES:
        raise HTTPException(status_code=422, detail="unknown module")
    with session_scope() as session:
        return search_documents(
            session,
            q=q,
            module=module,
            tech_direction=tech_direction,
            source=source,
            page=page,
            limit=limit,
        )


@router.get("/daily/archives")
def daily_archives() -> dict[str, Any]:
    """List natural dates with a frozen daily archive (newest first)."""
    with session_scope() as session:
        dates = list_archive_dates(session)
    return {"dates": dates}


@router.get("/daily/archives/{date_str}")
def daily_archive(date_str: str) -> dict[str, Any]:
    """Return a frozen daily archive payload for a natural day."""
    try:
        natural_date = date.fromisoformat(date_str)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="date must be YYYY-MM-DD") from exc
    with session_scope() as session:
        payload = get_archive(session, natural_date)
    if payload is None:
        raise HTTPException(status_code=404, detail="no archive for this date")
    return payload
