"""Immutable daily hotspot snapshots and as-of lookup."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, time
from hashlib import sha256
from zoneinfo import ZoneInfo

from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session

from ai_security_hot.models.tables import (
    DailyHotspotItem,
    DailyHotspotSnapshot,
    Document,
    Event,
    EventDocument,
    SourceEndpoint,
)
from ai_security_hot.storage.repositories import current_document_conditions


def generate_daily_snapshot(
    session: Session,
    *,
    natural_date: date,
    timezone: str = "Asia/Shanghai",
    category: str | None = None,
    limit: int = 100,
    min_score: int = 0,
) -> DailyHotspotSnapshot:
    """Freeze one immutable revision, reusing the latest if content is unchanged."""
    tzinfo = ZoneInfo(timezone)
    start = datetime.combine(natural_date, time.min, tzinfo=tzinfo)
    end = datetime.combine(natural_date, time.max, tzinfo=tzinfo)
    stmt = (
        select(
            Event,
            func.count(EventDocument.id),
            func.count(func.distinct(SourceEndpoint.source_id)),
        )
        .join(EventDocument, EventDocument.event_id == Event.id)
        .join(Document, Document.id == EventDocument.document_id)
        .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
        .where(
            Event.status == "detected",
            Event.score >= min_score,
            Event.last_seen_at >= start,
            Event.last_seen_at <= end,
            *current_document_conditions(),
        )
    )
    scope = category or "all"
    lock_key = f"daily-hotspot:{natural_date.isoformat()}:{timezone}:{scope}"
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": lock_key},
    )
    if category:
        stmt = stmt.where(Event.category == category)
    rows = session.execute(
        stmt.group_by(Event.id)
        .order_by(desc(Event.score), desc(Event.last_seen_at), desc(Event.id))
        .limit(limit)
    ).all()
    payloads = []
    for rank, (event, document_count, source_count) in enumerate(rows, 1):
        payloads.append(
            {
                "rank": rank,
                "event_id": int(event.id),
                "event_version": int(event.current_version),
                "score": int(event.score or 0),
                "payload": {
                    "id": event.id,
                    "fingerprint": event.fingerprint,
                    "event_type": event.event_type,
                    "topic": event.topic,
                    "category": event.category,
                    "title": event.title,
                    "summary": event.summary,
                    "status": event.status,
                    "score": event.score,
                    "evidence_level": event.evidence_level,
                    "document_count": int(document_count),
                    "source_count": int(source_count),
                    "first_seen_at": event.first_seen_at.isoformat()
                    if event.first_seen_at
                    else None,
                    "last_seen_at": event.last_seen_at.isoformat() if event.last_seen_at else None,
                    "current_version": event.current_version,
                    "cluster_version": event.cluster_version,
                    "updated_at": event.updated_at.isoformat(),
                },
            }
        )
    digest = sha256(json.dumps(payloads, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    latest = session.execute(
        select(DailyHotspotSnapshot)
        .where(
            DailyHotspotSnapshot.natural_date == natural_date,
            DailyHotspotSnapshot.timezone == timezone,
            DailyHotspotSnapshot.category == scope,
        )
        .order_by(desc(DailyHotspotSnapshot.revision))
        .limit(1)
        .with_for_update()
    ).scalar_one_or_none()
    if latest and latest.content_hash == digest:
        return latest
    snapshot = DailyHotspotSnapshot(
        natural_date=natural_date,
        timezone=timezone,
        category=scope,
        revision=latest.revision + 1 if latest else 1,
        generated_at=datetime.now(UTC),
        content_hash=digest,
        item_count=len(payloads),
    )
    session.add(snapshot)
    session.flush()
    for item in payloads:
        session.add(DailyHotspotItem(snapshot_id=snapshot.id, **item))
    session.flush()
    return snapshot


def read_daily_snapshot(
    session: Session,
    *,
    natural_date: date,
    timezone: str,
    category: str | None,
    as_of: datetime | None,
    limit: int,
    min_score: int,
) -> tuple[DailyHotspotSnapshot | None, list[dict]]:
    """Read the latest frozen revision at or before as_of."""
    scope = category or "all"
    stmt = select(DailyHotspotSnapshot).where(
        DailyHotspotSnapshot.natural_date == natural_date,
        DailyHotspotSnapshot.timezone == timezone,
        DailyHotspotSnapshot.category == scope,
    )
    if as_of is not None:
        stmt = stmt.where(DailyHotspotSnapshot.generated_at <= as_of)
    snapshot = session.execute(
        stmt.order_by(desc(DailyHotspotSnapshot.generated_at)).limit(1)
    ).scalar_one_or_none()
    if snapshot is None:
        return None, []
    items = session.execute(
        select(DailyHotspotItem)
        .where(
            DailyHotspotItem.snapshot_id == snapshot.id,
            DailyHotspotItem.score >= min_score,
        )
        .order_by(DailyHotspotItem.rank)
        .limit(limit)
    ).scalars()
    return snapshot, [
        {
            **item.payload,
            "snapshot_id": snapshot.id,
            "snapshot_revision": snapshot.revision,
            "snapshot_as_of": snapshot.generated_at.isoformat(),
            "event_version": item.event_version,
        }
        for item in items
    ]
