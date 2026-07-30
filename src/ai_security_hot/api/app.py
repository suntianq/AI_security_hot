"""FastAPI read/ops API (MVP §12 subset for M0).

Read-only views over the pipeline plus manual triggers for ops. The heavy
lifting lives in the worker; the API never fetches inline.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import desc, func, select

from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.jobs.self_check import run_self_check
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, RawItem, SourceEndpoint
from ai_security_hot.pipelines.stages import run_fetch_stage, run_normalize_stage

app = FastAPI(title="AI Security Hot — Intel Backend", version="0.1.0")


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
                "id": ep.id, "source_id": ep.source_id, "connector": ep.connector,
                "enabled": ep.enabled, "status": ep.status,
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
) -> list[dict]:
    with session_scope() as session:
        stmt = select(Document).where(Document.parse_quality >= min_quality)
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
                "id": d.id, "title": d.title_original, "url": d.canonical_url,
                "org": d.org, "language": d.language,
                "published_at": d.published_at_utc.isoformat() if d.published_at_utc else None,
                "identifiers": d.identifiers, "parse_quality": d.parse_quality,
                "tech_directions": d.tech_directions, "company_models": d.company_models,
                "event_type": d.classified_event_type, "classify_method": d.classify_method,
            }
            for d in rows
        ]


@app.get("/stats")
def stats() -> dict:
    with session_scope() as session:
        rows = session.execute(
            select(RawItem.stage, func.count()).group_by(RawItem.stage)
        ).all()
        by_stage = {stage: count for stage, count in rows}
        doc_count = session.execute(select(func.count()).select_from(Document)).scalar_one()
    return {
        "raw_items_by_stage": {str(k): int(v) for k, v in by_stage.items()},
        "documents": int(doc_count),
        "stages": [s.value for s in PipelineStage],
    }


@app.post("/ops/tick")
def ops_tick() -> dict:
    """Manually run one fetch + normalize pass (ops/testing convenience)."""
    fetch = run_fetch_stage()
    normalize = run_normalize_stage()
    return {"fetch": fetch, "normalize": normalize}


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
            "id": d.id, "title": d.title_original, "title_zh": d.title_zh,
            "body_text": d.body_text, "url": d.canonical_url, "org": d.org,
            "identifiers": d.identifiers, "entities": d.entities,
            "parse_quality": d.parse_quality,
        }
