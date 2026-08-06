"""Admin management API — privileged write routes under /ops/.

All routes here require the admin bearer token (enforced by the middleware on
any ``/ops/`` path). Provides document/event lifecycle edits (soft + hard
delete, manual re-tagging, re-queue for clustering), one-shot classify/cluster
triggers, taxonomy keyword management, and an auth-check used by the admin
login page.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Body, HTTPException
from sqlalchemy import delete

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, Event, EventDocument
from ai_security_hot.storage import repositories as repo

router = APIRouter(prefix="/ops", tags=["admin"])


# ---------------------------------------------------------------------------
# Auth check for the admin login page.
# ---------------------------------------------------------------------------
@router.get("/auth/check")
def auth_check() -> dict:
    """Return ok if the caller reached here with a valid admin token."""
    return {"ok": True, "scope": "admin"}


# ---------------------------------------------------------------------------
# Document management
# ---------------------------------------------------------------------------
class _TagsPayload(dict):
    """Body for PATCH /ops/documents/{id}: optional tag/classification fields."""


@router.patch("/documents/{document_id}")
def patch_document_tags(
    document_id: int,
    payload: dict = Body(...),  # noqa: B008
) -> dict:
    """Manually set a document's tags/classification.

    Accepts any subset of ``tech_directions`` / ``company_models`` /
    ``classified_event_type``. Marks the classification as ``manual`` and
    re-queues dedupe+cluster so derived events refresh.
    """
    allowed = {"tech_directions", "company_models", "classified_event_type"}
    updates = {k: v for k, v in payload.items() if k in allowed}
    if not updates:
        raise HTTPException(status_code=422, detail="no supported tag fields provided")

    from ai_security_hot.classify.base import Classification

    with session_scope() as session:
        doc = session.get(Document, document_id)
        if doc is None:
            raise HTTPException(status_code=404, detail=f"document {document_id} not found")

        # Reuse the classification write path so provenance + invalidation match.
        cls = Classification(
            tech_directions=list(updates.get("tech_directions", doc.tech_directions or [])),
            company_models=list(updates.get("company_models", doc.company_models or [])),
            event_type=updates.get("classified_event_type", doc.classified_event_type),
            confidence=1.0,
            method="manual",
            rule_version="manual",
            input_hash=doc.title_original or "",
        )
        # apply_classification expects an open lease; write directly and enqueue
        # the M2 invalidation ourselves to avoid the lease check.
        doc.tech_directions = cls.tech_directions
        doc.company_models = cls.company_models
        doc.classified_event_type = cls.event_type
        doc.classify_method = "manual"
        doc.classify_confidence = 1.0
        from datetime import UTC, datetime

        doc.classified_at = datetime.now(UTC)
        repo._enqueue_m2_change(session, [document_id], reason="manual_tag", include_dedupe=False)

    return {
        "document_id": document_id,
        "tech_directions": doc.tech_directions,
        "company_models": doc.company_models,
        "classified_event_type": doc.classified_event_type,
        "classify_method": "manual",
    }


@router.patch("/documents/{document_id}/status")
def patch_document_status(
    document_id: int,
    payload: dict = Body(...),  # noqa: B008
) -> dict:
    """Soft-delete / restore a document via lifecycle state.

    body: ``{kind: "source"|"record", status: "...", reason?: "..."}``
    """
    kind = payload.get("kind", "source")
    status = payload.get("status")
    reason = payload.get("reason")
    if kind not in ("source", "record"):
        raise HTTPException(status_code=422, detail="kind must be 'source' or 'record'")
    if not isinstance(status, str) or not status:
        raise HTTPException(status_code=422, detail="status is required")

    with session_scope() as session:
        doc = session.get(Document, document_id)
        if doc is None:
            raise HTTPException(status_code=404, detail=f"document {document_id} not found")
        if kind == "source":
            doc.source_status = status
            doc.source_status_reason = reason
        else:
            doc.record_status = status
            doc.record_status_raw = reason
        repo._enqueue_m2_change(session, [document_id], reason="admin_status_change")

    return {"document_id": document_id, "status": status, "kind": kind}


@router.delete("/documents/{document_id}")
def delete_document(document_id: int) -> dict:
    """Physically delete a document and its event links.

    Event links (EventDocument) are removed first; the Document row is then
    deleted. RawItem evidence is kept (immutable history).
    """
    with session_scope() as session:
        doc = session.get(Document, document_id)
        if doc is None:
            raise HTTPException(status_code=404, detail=f"document {document_id} not found")
        session.execute(delete(EventDocument).where(EventDocument.document_id == document_id))
        session.delete(doc)

    return {"document_id": document_id, "deleted": True}


@router.post("/documents/{document_id}/requeue")
def requeue_document(document_id: int) -> dict:
    """Re-enqueue a single document for re-dedupe + re-cluster (incremental)."""
    from ai_security_hot.storage.event_repository import (
        CLUSTER_VERSION,
        DEDUPE_VERSION,
        enqueue_work,
    )

    with session_scope() as session:
        doc = session.get(Document, document_id)
        if doc is None:
            raise HTTPException(status_code=404, detail=f"document {document_id} not found")
        enqueue_work(
            session,
            {document_id},
            stage="dedupe",
            reason="admin_requeue",
            algorithm_version=DEDUPE_VERSION,
        )
        enqueue_work(
            session,
            {document_id},
            stage="cluster",
            reason="admin_requeue",
            algorithm_version=CLUSTER_VERSION,
        )

    return {"document_id": document_id, "queued": True}


# ---------------------------------------------------------------------------
# Event management
# ---------------------------------------------------------------------------
@router.patch("/events/{event_id}/status")
def patch_event_status(
    event_id: int,
    payload: dict = Body(...),  # noqa: B008
) -> dict:
    """Soft-delete / restore an event via its status field.

    body: ``{status: "superseded"|"detected", reason?: "..."}``
    """
    status = payload.get("status")
    if status not in ("superseded", "detected"):
        raise HTTPException(status_code=422, detail="status must be 'superseded' or 'detected'")
    with session_scope() as session:
        evt = session.get(Event, event_id)
        if evt is None:
            raise HTTPException(status_code=404, detail=f"event {event_id} not found")
        evt.status = status

    return {"event_id": event_id, "status": status}


@router.delete("/events/{event_id}")
def delete_event(event_id: int) -> dict:
    """Physically delete an event (cascades to EventDocument / EventVersion)."""
    with session_scope() as session:
        evt = session.get(Event, event_id)
        if evt is None:
            raise HTTPException(status_code=404, detail=f"event {event_id} not found")
        session.delete(evt)

    return {"event_id": event_id, "deleted": True}


# ---------------------------------------------------------------------------
# One-shot pipeline triggers
# ---------------------------------------------------------------------------
@router.post("/classify")
def trigger_classify() -> dict:
    """Run one incremental classification pass (returns per-stage summary)."""
    from ai_security_hot.pipelines.stages import run_classify_stage

    return run_classify_stage()


@router.post("/cluster")
def trigger_cluster() -> dict:
    """Run one incremental dedupe + cluster pass."""
    from ai_security_hot.pipelines.stages import run_cluster_stage, run_dedupe_stage

    dedupe = run_dedupe_stage()
    cluster = run_cluster_stage()
    return {"dedupe": dedupe, "cluster": cluster}


# ---------------------------------------------------------------------------
# Taxonomy (tag vocabulary) management
# ---------------------------------------------------------------------------
_TAXONOMY_PATH = Path("sources/taxonomy.yaml")


def _load_taxonomy_file() -> dict:
    import yaml

    return yaml.safe_load(_TAXONOMY_PATH.read_text(encoding="utf-8")) or {}


def _write_taxonomy_file(data: dict) -> None:
    import yaml

    # Mixed flow style: nested dicts expand block-style, lists stay inline
    # (["a", "b"]) so the file stays close to the hand-edited layout. Comment
    # blocks in the YAML are intentionally lost on write — taxonomy edits via
    # the admin UI are authoritative and infrequent.
    _TAXONOMY_PATH.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=None),
        encoding="utf-8",
    )
    from ai_security_hot.classify.taxonomy import load_taxonomy

    load_taxonomy.cache_clear()


@router.get("/taxonomy")
def get_taxonomy() -> dict:
    """Return the current tag vocabulary (tech directions / company models)."""
    data = _load_taxonomy_file()
    tech = data.get("tech_directions", {})
    return {
        "tech_directions": {k: v.get("keywords", []) for k, v in tech.items()},
        "company_models": data.get("company_models", {}),
    }


@router.post("/taxonomy/tags")
def add_taxonomy_tag(
    payload: dict = Body(...),  # noqa: B008
) -> dict:
    """Add a keyword to a taxonomy bucket.

    body: ``{bucket: "tech_directions"|"company_models", tag: "...", keyword: "..."}``
    """
    bucket = payload.get("bucket")
    tag = payload.get("tag")
    keyword = payload.get("keyword")
    if bucket not in ("tech_directions", "company_models") or not tag or not keyword:
        raise HTTPException(status_code=422, detail="bucket/tag/keyword are required")

    data = _load_taxonomy_file()
    if bucket == "tech_directions":
        bucket_data = data.setdefault("tech_directions", {})
        tag_cfg = bucket_data.setdefault(tag, {})
        keywords = tag_cfg.setdefault("keywords", [])
        if keyword not in keywords:
            keywords.append(keyword)
    else:
        bucket_data = data.setdefault("company_models", {})
        keywords = bucket_data.setdefault(tag, [])
        if keyword not in keywords:
            keywords.append(keyword)
    _write_taxonomy_file(data)
    return {"bucket": bucket, "tag": tag, "keyword": keyword, "added": True}


@router.delete("/taxonomy/tags")
def delete_taxonomy_tag(
    payload: dict = Body(...),  # noqa: B008
) -> dict:
    """Remove a keyword from a taxonomy bucket."""
    bucket = payload.get("bucket")
    tag = payload.get("tag")
    keyword = payload.get("keyword")
    if bucket not in ("tech_directions", "company_models") or not tag or not keyword:
        raise HTTPException(status_code=422, detail="bucket/tag/keyword are required")

    data = _load_taxonomy_file()
    removed = False
    if bucket == "tech_directions":
        keywords = (data.get("tech_directions") or {}).get(tag, {}).get("keywords", [])
        if keyword in keywords:
            keywords.remove(keyword)
            removed = True
    else:
        keywords = (data.get("company_models") or {}).get(tag, [])
        if keyword in keywords:
            keywords.remove(keyword)
            removed = True
    if removed:
        _write_taxonomy_file(data)
    return {"bucket": bucket, "tag": tag, "keyword": keyword, "removed": removed}
