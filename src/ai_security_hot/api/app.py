"""FastAPI read/ops API (MVP §12 subset for M0).

Read-only views over the pipeline plus manual triggers for ops. Read routes use
``INTEL_API_TOKEN``; privileged ``/ops/*`` routes use the separate
``INTEL_ADMIN_API_TOKEN``. Health probes remain unauthenticated.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from functools import lru_cache

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import desc, func, select, text
from sqlalchemy.exc import SQLAlchemyError

from ai_security_hot.config.settings import get_settings
from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.jobs.self_check import run_self_check
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import (
    Document,
    Event,
    EventDocument,
    ModelRun,
    RawItem,
    Source,
    SourceEndpoint,
)
from ai_security_hot.storage import repositories as repo

app = FastAPI(title="AI Security Hot — Intel Backend", version="0.2.0")


_PUBLIC_HEALTH_PATHS = {"/health", "/health/live", "/health/ready"}

# Public read-only aggregations for the public frontend (no token needed — the
# browser page cannot carry a bearer token). Admin mutations stay under /ops/.
_PUBLIC_API_PREFIXES = ("/api/",)

# Static frontend files (pages + assets) are public; admin auth is enforced in
# the SPA by redirecting to /login.html before any /ops/ call.
_PUBLIC_STATIC = {
    "/",
    "/index.html",
    "/admin.html",
    "/login.html",
    "/document.html",
    "/event.html",
    "/daily.html",
    "/favicon.ico",
}
_PUBLIC_STATIC_PREFIXES = ("/assets/",)


# --- admin + frontend routers (imported after app exists to attach routes) ---
from ai_security_hot.api.admin import router as admin_router  # noqa: E402
from ai_security_hot.api.frontend import router as frontend_router  # noqa: E402

app.include_router(frontend_router)
app.include_router(admin_router)


@app.middleware("http")
async def _require_bearer_token(request: Request, call_next) -> Response:
    """Use separate fail-closed tokens for read and administrative routes."""
    path = request.url.path
    if path in _PUBLIC_HEALTH_PATHS:
        return await call_next(request)
    if path.startswith(_PUBLIC_API_PREFIXES):
        return await call_next(request)
    if path in _PUBLIC_STATIC or path.startswith(_PUBLIC_STATIC_PREFIXES):
        return await call_next(request)

    settings = get_settings()
    is_admin = request.url.path.startswith("/ops/")
    if is_admin:
        # Mutations / admin routes require the admin token only.
        expected = settings.admin_api_token
        name = "INTEL_ADMIN_API_TOKEN"
    else:
        # Read routes accept either the read token or the admin token (admin is
        # a superset, so the management console can read with one credential).
        expected = settings.api_token
        name = "INTEL_API_TOKEN"
    if not expected:
        # Admin may fall back to the read token for read routes if unset.
        if not is_admin and settings.admin_api_token:
            expected = settings.admin_api_token
            name = "INTEL_ADMIN_API_TOKEN"
        if not expected:
            return JSONResponse(
                status_code=503,
                content={"detail": f"{name} is not configured"},
            )

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "unauthorized"})
    provided = header.removeprefix("Bearer ")
    if not provided:
        return JSONResponse(status_code=401, content={"detail": "unauthorized"})
    if secrets.compare_digest(provided, expected):
        return await call_next(request)
    # Read routes additionally accept the admin token when provided.
    if not is_admin and settings.admin_api_token and secrets.compare_digest(
        provided, settings.admin_api_token
    ):
        return await call_next(request)
    return JSONResponse(status_code=401, content={"detail": "unauthorized"})


@lru_cache
def _expected_schema_heads() -> frozenset[str]:
    config = Config("alembic.ini")
    return frozenset(ScriptDirectory.from_config(config).get_heads())


@app.get("/health")
@app.get("/health/live")
def health_live() -> dict:
    """Process liveness only; it stays independent from database availability."""
    return {"status": "ok", "build_sha": get_settings().build_sha}


@app.get("/health/ready")
def health_ready() -> dict:
    """Readiness requires database connectivity and this image's exact schema."""
    try:
        with session_scope() as session:
            current = frozenset(
                session.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            )
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="database unavailable") from None

    expected = _expected_schema_heads()
    if current != expected:
        raise HTTPException(
            status_code=503,
            detail={"schema": "mismatch", "current": sorted(current), "expected": sorted(expected)},
        )
    return {
        "status": "ready",
        "build_sha": get_settings().build_sha,
        "schema_heads": sorted(current),
    }


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
                "replacement_endpoint_id": ep.replacement_endpoint_id,
                "retired_at": ep.retired_at.isoformat() if ep.retired_at else None,
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
    source_id: str | None = Query(None),
    record_status: str | None = Query(None),
    include_inactive: bool = Query(
        False, description="Include retired/superseded/withdrawn/rejected history"
    ),
) -> list[dict]:
    with session_scope() as session:
        stmt = (
            select(Document, SourceEndpoint, Source)
            .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .where(Document.parse_quality >= min_quality)
        )
        if not include_inactive:
            stmt = stmt.where(*repo.current_document_conditions())
        if tech_direction:
            stmt = stmt.where(Document.tech_directions.contains([tech_direction]))
        if company_model:
            stmt = stmt.where(Document.company_models.contains([company_model]))
        if event_type:
            stmt = stmt.where(Document.classified_event_type == event_type)
        if source_id:
            stmt = stmt.where(SourceEndpoint.source_id == source_id)
        if record_status:
            stmt = stmt.where(Document.record_status == record_status)
        stmt = stmt.order_by(desc(Document.id)).limit(limit)
        rows = session.execute(stmt).all()
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
                "source_id": endpoint.source_id,
                "source_name": source.name,
                "endpoint_id": endpoint.id,
                "endpoint_enabled": endpoint.enabled,
                "endpoint_status": endpoint.status,
                "source_status": d.source_status,
                "source_status_reason": d.source_status_reason,
                "record_status": d.record_status,
                "record_status_raw": d.record_status_raw,
            }
            for d, endpoint, source in rows
        ]


def _event_payload(event: Event, *, document_count: int, source_count: int) -> dict:
    return {
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
                *repo.current_document_conditions(),
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
                "source_status_reason": doc.source_status_reason,
                "record_status": doc.record_status,
                "record_status_raw": doc.record_status_raw,
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
        current_doc_count = session.execute(
            select(func.count()).select_from(Document).where(*repo.current_document_conditions())
        ).scalar_one()
        doc_status_rows = session.execute(
            select(Document.source_status, func.count()).group_by(Document.source_status)
        ).all()
        record_status_rows = session.execute(
            select(Document.record_status, func.count()).group_by(Document.record_status)
        ).all()
        endpoint_status_rows = session.execute(
            select(SourceEndpoint.status, func.count()).group_by(SourceEndpoint.status)
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
        "current_documents": int(current_doc_count),
        "documents_by_source_status": {str(k): int(v) for k, v in doc_status_rows},
        "documents_by_record_status": {str(k): int(v) for k, v in record_status_rows},
        "endpoints_by_status": {str(k): int(v) for k, v in endpoint_status_rows},
        "model_runs_by_status": {str(k): int(v) for k, v in model_status_rows},
        "near_duplicates": int(duplicate_count),
        "events": int(event_count),
        "event_documents": int(evidence_count),
        "stages": [s.value for s in PipelineStage],
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
            "source_status_reason": d.source_status_reason,
            "record_status": d.record_status,
            "record_status_raw": d.record_status_raw,
            "withdrawn_at": d.withdrawn_at.isoformat() if d.withdrawn_at else None,
            "classify_error": d.classify_error,
        }


# --- CORS for the SPA/admin pages (internal deployment) ---
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

_settings = get_settings()
_cors_origins = [o.strip() for o in (_settings.cors_origins or "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# --- Public static frontend (web/dist), mounted last so API routes take priority ---
from pathlib import Path  # noqa: E402

if _settings.web_dir:
    _web_path = Path(_settings.web_dir)
    if _web_path.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(_web_path), html=True), name="web")
