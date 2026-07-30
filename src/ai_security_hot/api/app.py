"""FastAPI read/ops API (MVP §12 subset for M0).

Read-only views over the pipeline plus manual triggers for ops. The heavy
lifting lives in the worker; the API never fetches inline.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import desc, func, select

from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.jobs.self_check import run_self_check
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import (
    Document,
    Event,
    EventDocument,
    ModelRun,
    RawItem,
    SourceEndpoint,
)
from ai_security_hot.pipelines.stages import (
    run_classify_stage,
    run_cluster_stage,
    run_dedupe_stage,
    run_fetch_stage,
    run_fulltext_stage,
    run_normalize_stage,
)

app = FastAPI(title="AI Security Hot — Intel Backend", version="0.2.0")


@app.get("/health")
def health() -> dict:
    with session_scope() as session:
        session.execute(select(1))
    return {"status": "ok"}


@app.get("/sources")
def list_sources() -> list[dict]:
    with session_scope() as session:
        rows = session.execute(select(SourceEndpoint)).scalars().all()
        return [
            {
                "id": ep.id,
                "source_id": ep.source_id,
                "connector": ep.connector,
                "enabled": ep.enabled,
                "status": ep.status,
                "state_version": ep.state_version,
                "egress_route": ep.egress_route,
                "consecutive_failures": ep.consecutive_failures,
                "last_success_at": ep.last_success_at.isoformat() if ep.last_success_at else None,
                "next_run_at": ep.next_run_at.isoformat() if ep.next_run_at else None,
            }
            for ep in rows
        ]


@app.get("/documents")
def list_documents(
    limit: int = Query(20, le=100),
    min_quality: float = Query(0.0, ge=0.0, le=1.0),
    tech_direction: str | None = Query(
        None,
        description="cve|llm|agent|ai_for_security|security_for_ai|system_security",
    ),
    company_model: str | None = Query(None, description="e.g. anthropic, openai"),
    event_type: str | None = Query(None),
    include_inactive: bool = Query(False),
) -> list[dict]:
    with session_scope() as session:
        stmt = select(Document).where(Document.parse_quality >= min_quality)
        if not include_inactive:
            stmt = stmt.where(Document.source_status == "active")
        if tech_direction:
            stmt = stmt.where(Document.tech_directions.contains([tech_direction]))
        if company_model:
            stmt = stmt.where(Document.company_models.contains([company_model]))
        if event_type:
            stmt = stmt.where(Document.classified_event_type == event_type)
        stmt = stmt.order_by(desc(Document.id)).limit(limit)
        rows = session.execute(stmt).scalars().all()
        return [
            {
                "id": d.id,
                "title": d.title_original,
                "url": d.canonical_url,
                "org": d.org,
                "language": d.language,
                "published_at": d.published_at_utc.isoformat() if d.published_at_utc else None,
                "identifiers": d.identifiers,
                "parse_quality": d.parse_quality,
                "tech_directions": d.tech_directions,
                "company_models": d.company_models,
                "event_type": d.classified_event_type,
                "classify_method": d.classify_method,
                "source_status": d.source_status,
            }
            for d in rows
        ]


def _event_payload(event: Event, *, document_count: int, source_count: int) -> dict:
    return {
        "id": event.id,
        "fingerprint": event.fingerprint,
        "event_type": event.event_type,
        "topic": event.topic,
        "title": event.title,
        "summary": event.summary,
        "status": event.status,
        "score": event.score,
        "evidence_level": event.evidence_level,
        "document_count": document_count,
        "source_count": source_count,
        "first_seen_at": event.first_seen_at.isoformat() if event.first_seen_at else None,
        "last_seen_at": event.last_seen_at.isoformat() if event.last_seen_at else None,
        "current_version": event.current_version,
        "cluster_version": event.cluster_version,
        "updated_at": event.updated_at.isoformat(),
    }


@app.get("/events")
def list_events(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    topic: str | None = Query(None),
    event_type: str | None = Query(None),
    evidence_level: str | None = Query(None, description="A|B|C"),
    min_score: int = Query(0, ge=0, le=100),
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[dict]:
    """List current materialized events with evidence/source counts."""
    with session_scope() as session:
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
                Document.source_status == "active",
            )
        )
        if topic:
            stmt = stmt.where(Event.topic == topic)
        if event_type:
            stmt = stmt.where(Event.event_type == event_type)
        if evidence_level:
            stmt = stmt.where(Event.evidence_level == evidence_level.upper())
        if since:
            stmt = stmt.where(Event.last_seen_at >= since)
        if until:
            stmt = stmt.where(Event.first_seen_at <= until)
        stmt = (
            stmt.group_by(Event.id)
            .order_by(desc(Event.score), desc(Event.last_seen_at), desc(Event.id))
            .offset(offset)
            .limit(limit)
        )
        rows = session.execute(stmt).all()
        return [
            _event_payload(event, document_count=int(doc_count), source_count=int(source_count))
            for event, doc_count, source_count in rows
        ]


@app.get("/events/{event_id}")
def get_event(event_id: int) -> dict:
    """Return an event and every retained source document used as evidence."""
    with session_scope() as session:
        event = session.get(Event, event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        rows = session.execute(
            select(EventDocument, Document, SourceEndpoint)
            .join(Document, Document.id == EventDocument.document_id)
            .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
            .where(EventDocument.event_id == event_id)
            .order_by(EventDocument.evidence_level, desc(Document.published_at_utc), Document.id)
        ).all()
        source_count = len({endpoint.source_id for _link, _doc, endpoint in rows})
        payload = _event_payload(event, document_count=len(rows), source_count=source_count)
        payload["evidence"] = [
            {
                "document_id": doc.id,
                "source_id": endpoint.source_id,
                "endpoint_id": doc.endpoint_id,
                "trust_tier": link.evidence_level,
                "relation_reason": link.relation_reason,
                "title": doc.title_original,
                "url": doc.canonical_url,
                "published_at": (
                    doc.published_at_utc.isoformat() if doc.published_at_utc else None
                ),
                "parse_quality": doc.parse_quality,
                "source_status": doc.source_status,
            }
            for link, doc, endpoint in rows
        ]
        return payload


@app.get("/stats")
def stats() -> dict:
    with session_scope() as session:
        rows = session.execute(select(RawItem.stage, func.count()).group_by(RawItem.stage)).all()
        by_stage = {stage: count for stage, count in rows}
        doc_count = session.execute(select(func.count()).select_from(Document)).scalar_one()
        doc_status_rows = session.execute(
            select(Document.source_status, func.count()).group_by(Document.source_status)
        ).all()
        model_status_rows = session.execute(
            select(ModelRun.status, func.count()).group_by(ModelRun.status)
        ).all()
        duplicate_count = session.execute(
            select(func.count()).select_from(Document).where(Document.near_dup_of.is_not(None))
        ).scalar_one()
        event_count = session.execute(
            select(func.count()).select_from(Event).where(Event.status == "detected")
        ).scalar_one()
        evidence_count = session.execute(
            select(func.count()).select_from(EventDocument)
        ).scalar_one()
    return {
        "raw_items_by_stage": {str(k): int(v) for k, v in by_stage.items()},
        "documents": int(doc_count),
        "documents_by_source_status": {str(k): int(v) for k, v in doc_status_rows},
        "model_runs_by_status": {str(k): int(v) for k, v in model_status_rows},
        "near_duplicates": int(duplicate_count),
        "events": int(event_count),
        "event_documents": int(evidence_count),
        "stages": [s.value for s in PipelineStage],
    }


@app.post("/ops/tick")
def ops_tick() -> dict:
    """Manually run one complete incremental pipeline pass."""
    fetch = run_fetch_stage()
    normalize = run_normalize_stage()
    fulltext = run_fulltext_stage()
    classify = run_classify_stage()
    dedupe = run_dedupe_stage()
    cluster = run_cluster_stage()
    return {
        "fetch": fetch,
        "normalize": normalize,
        "fulltext": fulltext,
        "classify": classify,
        "dedupe": dedupe,
        "cluster": cluster,
    }


@app.get("/ops/self-check")
def ops_self_check() -> dict:
    return run_self_check()


@app.get("/documents/{document_id}")
def get_document(document_id: int) -> dict:
    with session_scope() as session:
        d = session.get(Document, document_id)
        if d is None:
            raise HTTPException(status_code=404, detail="document not found")
        return {
            "id": d.id,
            "title": d.title_original,
            "title_zh": d.title_zh,
            "body_text": d.body_text,
            "url": d.canonical_url,
            "org": d.org,
            "identifiers": d.identifiers,
            "entities": d.entities,
            "parse_quality": d.parse_quality,
            "source_status": d.source_status,
            "withdrawn_at": d.withdrawn_at.isoformat() if d.withdrawn_at else None,
            "classify_error": d.classify_error,
        }
