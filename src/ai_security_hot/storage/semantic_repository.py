"""Leased shadow-semantic work and immutable enrichment persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.domain.models import NormalizedDocument, content_sha256
from ai_security_hot.domain.semantic import (
    DocumentSemanticOutput,
    ExtractedEntity,
    canonical_entity_text,
    locate_evidence,
)
from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    DocumentEnrichment,
    EntityMention,
    ExtractedClaim,
    SemanticEntity,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import Document, RawItem
from ai_security_hot.storage.repositories import current_document_conditions, is_current_document


class SemanticLeaseLost(RuntimeError):
    """A stale semantic worker may not persist or audit its result."""


@dataclass(frozen=True)
class ClaimedDocumentWork:
    work_item_id: int
    document_id: int
    attempts: int
    lease_token: str
    document: NormalizedDocument


def _document_dto(document: Document) -> NormalizedDocument:
    identifiers = document.identifiers or {}
    return NormalizedDocument(
        raw_item_native_id=str(document.raw_item_id),
        endpoint_id=document.endpoint_id,
        title_original=document.title_original,
        title_zh=document.title_zh,
        body_text=document.body_text,
        canonical_url=document.canonical_url,
        author=document.author,
        org=document.org,
        published_at_utc=document.published_at_utc,
        language=document.language,
        cve_ids=identifiers.get("cve", []),
        ghsa_ids=identifiers.get("ghsa", []),
        cnvd_ids=identifiers.get("cnvd", []),
        cwe_ids=identifiers.get("cwe", []),
        entities=document.entities or {},
        record_status=document.record_status,
        record_status_raw=document.record_status_raw,
        parse_quality=document.parse_quality,
    )


def enqueue_document_work(
    session: Session,
    *,
    task: str,
    task_version: str,
    execution_version: str,
    mode: str,
    limit: int,
    batch_id: str | None = None,
    document_ids: list[int] | None = None,
) -> int:
    """Queue current non-CVE duplicate masters exactly once per execution.

    If ``document_ids`` is provided, only those documents are enqueued (used by
    controlled eval sampling); otherwise the most recent eligible docs are used.
    """

    already_queued = (
        select(SemanticWorkItem.id)
        .where(
            SemanticWorkItem.subject_type == "document",
            SemanticWorkItem.subject_id == Document.id,
            SemanticWorkItem.task == task,
            SemanticWorkItem.execution_version == execution_version,
        )
        .exists()
    )
    base_conditions = [
        *current_document_conditions(),
        RawItem.stage == "done",
        Document.classified_at.is_not(None),
        Document.tech_directions != ["cve"],
        func.coalesce(Document.identifiers["cve"].astext, "[]") == "[]",
        func.coalesce(Document.identifiers["ghsa"].astext, "[]") == "[]",
        func.coalesce(Document.identifiers["cnvd"].astext, "[]") == "[]",
        Document.dedupe_version.is_not(None),
        Document.near_dup_of.is_(None),
        ~already_queued,
    ]
    if document_ids is not None:
        base_conditions.append(Document.id.in_(document_ids))
    document_ids = list(
        session.execute(
            select(Document.id)
            .join(RawItem, RawItem.id == Document.raw_item_id)
            .where(
                *base_conditions,
            )
            .order_by(Document.id)
            .limit(limit)
        ).scalars()
    )
    if not document_ids:
        return 0
    inserted = list(
        session.execute(
            pg_insert(SemanticWorkItem)
            .values(
                [
                    {
                        "subject_type": "document",
                        "subject_id": int(document_id),
                        "task": task,
                        "task_version": task_version,
                        "execution_version": execution_version,
                        "mode": mode,
                        "status": "pending",
                        "batch_id": batch_id,
                    }
                    for document_id in document_ids
                ]
            )
            .on_conflict_do_nothing(constraint="uq_semantic_work_execution")
            .returning(SemanticWorkItem.id)
        ).scalars()
    )
    session.flush()
    return len(inserted)


def _reconcile_orphan_succeeded_work(
    session: Session, *, task: str, execution_version: str
) -> None:
    """Mark 'succeeded' work items that have no enrichment row as failed.

    A work item can be left 'succeeded' without a DocumentEnrichment if a prior
    crash or partial write completed the work status before persisting the
    enrichment. Leaving them 'succeeded' hides them from both retry and audit.
    """
    orphan_ids = session.execute(
        select(SemanticWorkItem.id)
        .outerjoin(
            DocumentEnrichment, DocumentEnrichment.work_item_id == SemanticWorkItem.id
        )
        .where(
            SemanticWorkItem.task == task,
            SemanticWorkItem.execution_version == execution_version,
            SemanticWorkItem.status == "succeeded",
            DocumentEnrichment.id.is_(None),
        )
    ).scalars().all()
    if not orphan_ids:
        return
    session.execute(
        update(SemanticWorkItem)
        .where(SemanticWorkItem.id.in_(orphan_ids))
        .values(
            status="failed",
            error="succeeded work item has no enrichment row (reconciled)",
            updated_at=datetime.now(UTC),
        )
    )
    session.flush()


def claim_document_work(
    session: Session,
    *,
    task: str,
    execution_version: str,
    limit: int,
    lease_seconds: int,
    batch_id: str | None = None,
) -> list[ClaimedDocumentWork]:
    now = datetime.now(UTC)
    eligible = or_(
        SemanticWorkItem.status == "pending",
        (
            (SemanticWorkItem.status == "retry")
            & (SemanticWorkItem.next_retry_at.is_(None) | (SemanticWorkItem.next_retry_at <= now))
        ),
        (
            (SemanticWorkItem.status == "running")
            & SemanticWorkItem.lease_until.is_not(None)
            & (SemanticWorkItem.lease_until < now)
        ),
    )
    conditions = [
        SemanticWorkItem.subject_type == "document",
        SemanticWorkItem.task == task,
        SemanticWorkItem.execution_version == execution_version,
        eligible,
    ]
    if batch_id is not None:
        conditions.append(SemanticWorkItem.batch_id == batch_id)
    _reconcile_orphan_succeeded_work(session, task=task, execution_version=execution_version)
    rows = list(
        session.execute(
            select(SemanticWorkItem)
            .where(*conditions)
            .order_by(SemanticWorkItem.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    if not rows:
        return []
    token = token_urlsafe(32)
    lease_until = now + timedelta(seconds=lease_seconds)
    for row in rows:
        row.status = "running"
        row.lease_token = token
        row.lease_until = lease_until
        row.attempts = (row.attempts or 0) + 1
        row.updated_at = now

    documents = {
        int(document.id): document
        for document in session.execute(
            select(Document).where(
                Document.id.in_([row.subject_id for row in rows]),
                *current_document_conditions(),
            )
        ).scalars()
    }
    claimed: list[ClaimedDocumentWork] = []
    for row in rows:
        document = documents.get(int(row.subject_id))
        if document is None:
            row.status = "cancelled"
            row.lease_token = None
            row.lease_until = None
            row.error = "document is no longer current"
            continue
        claimed.append(
            ClaimedDocumentWork(
                work_item_id=int(row.id),
                document_id=int(document.id),
                attempts=int(row.attempts),
                lease_token=token,
                document=_document_dto(document),
            )
        )
    session.flush()
    return claimed


def extend_work_leases(
    session: Session,
    work_item_ids: list[int],
    lease_token: str,
    *,
    lease_seconds: int,
) -> set[int]:
    if not work_item_ids:
        return set()
    owned = session.execute(
        update(SemanticWorkItem)
        .where(
            SemanticWorkItem.id.in_(work_item_ids),
            SemanticWorkItem.status == "running",
            SemanticWorkItem.lease_token == lease_token,
        )
        .values(
            lease_until=datetime.now(UTC) + timedelta(seconds=lease_seconds),
            updated_at=datetime.now(UTC),
        )
        .returning(SemanticWorkItem.id)
    ).scalars()
    session.flush()
    return {int(work_item_id) for work_item_id in owned}


def _locked_owned_work(
    session: Session,
    work_item_id: int,
    lease_token: str,
) -> SemanticWorkItem:
    row = session.execute(
        select(SemanticWorkItem).where(SemanticWorkItem.id == work_item_id).with_for_update()
    ).scalar_one_or_none()
    if (
        row is None
        or row.status != "running"
        or row.lease_token != lease_token
        or row.subject_type != "document"
    ):
        raise SemanticLeaseLost(f"semantic lease lost: {work_item_id}")
    return row


def _upsert_entity(session: Session, entity: ExtractedEntity) -> int:
    canonical_name = (entity.canonical_name or entity.name).strip()
    canonical_key = content_sha256(
        entity.entity_type,
        canonical_entity_text(canonical_name),
        canonical_entity_text(entity.version or ""),
    )
    now = datetime.now(UTC)
    entity_id = session.execute(
        pg_insert(SemanticEntity)
        .values(
            canonical_key=canonical_key,
            entity_type=entity.entity_type,
            canonical_name=canonical_name,
            version=entity.version,
            aliases=[entity.name],
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[SemanticEntity.canonical_key],
            set_={"updated_at": now},
        )
        .returning(SemanticEntity.id)
    ).scalar_one()
    return int(entity_id)


def _add_entity_mention(
    session: Session,
    *,
    entity: ExtractedEntity,
    document_id: int,
    enrichment_id: int,
    atomic_event_id: int | None,
    title: str,
    body: str | None,
) -> None:
    entity_id = _upsert_entity(session, entity)
    location = locate_evidence(title, body, entity.evidence.text)
    session.add(
        EntityMention(
            entity_id=entity_id,
            document_id=document_id,
            enrichment_id=enrichment_id,
            atomic_event_id=atomic_event_id,
            mention_text=entity.name,
            role=entity.role,
            confidence=entity.confidence,
            evidence_excerpt=entity.evidence.text,
            evidence_field=location.field,
            evidence_start=location.start,
            evidence_end=location.end,
        )
    )


def complete_document_work(
    session: Session,
    *,
    work_item_id: int,
    lease_token: str,
    document: NormalizedDocument,
    output: DocumentSemanticOutput,
    input_hash: str,
    execution_version: str,
    enrichment_version: str,
    provider: str,
    model: str,
    prompt_version: str,
    finish_reason: str | None = None,
    usage: dict | None = None,
    raw_response: str | None = None,
    batch_id: str | None = None,
) -> int:
    """Persist one validated output and all child rows in one transaction."""

    work = _locked_owned_work(session, work_item_id, lease_token)
    document_id = int(work.subject_id)
    document_row = session.get(Document, document_id)
    if document_row is None or not is_current_document(
        document_row.source_status, document_row.record_status
    ):
        raise SemanticLeaseLost(f"document is no longer current: {document_id}")

    existing = session.execute(
        select(DocumentEnrichment).where(DocumentEnrichment.work_item_id == work_item_id)
    ).scalar_one_or_none()
    if existing is not None:
        work.status = "succeeded"
        work.lease_token = None
        work.lease_until = None
        work.updated_at = datetime.now(UTC)
        return int(existing.id)

    enrichment = DocumentEnrichment(
        work_item_id=work_item_id,
        document_id=document_id,
        enrichment_version=enrichment_version,
        execution_version=execution_version,
        mode=work.mode,
        input_hash=input_hash,
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        relevant=output.relevant,
        relevance_confidence=output.relevance_confidence,
        content_type=output.content_type,
        summary=output.summary,
        output=output.model_dump(mode="json"),
        finish_reason=finish_reason,
        usage=usage or {},
        raw_response=raw_response,
        # Prefer the work item's original batch so aggregation never crosses
        # batches even when a later run with a different --batch claims it.
        batch_id=work.batch_id or batch_id,
    )
    session.add(enrichment)
    session.flush()

    for entity in output.entities:
        _add_entity_mention(
            session,
            entity=entity,
            document_id=document_id,
            enrichment_id=int(enrichment.id),
            atomic_event_id=None,
            title=document.title_original,
            body=document.body_text,
        )

    for ordinal, extracted in enumerate(output.atomic_events):
        fingerprint = content_sha256(
            canonical_entity_text(extracted.event_type),
            canonical_entity_text(extracted.subject),
            canonical_entity_text(extracted.action),
            canonical_entity_text(extracted.object or ""),
            canonical_entity_text(extracted.time_text or ""),
        )
        atomic_event = AtomicEvent(
            enrichment_id=enrichment.id,
            document_id=document_id,
            ordinal=ordinal,
            fingerprint=fingerprint,
            event_type=extracted.event_type,
            subject=extracted.subject,
            action=extracted.action,
            object=extracted.object,
            time_text=extracted.time_text,
            location=extracted.location,
            summary=extracted.summary,
            confidence=extracted.confidence,
            evidence=[quote.model_dump(mode="json") for quote in extracted.evidence],
            mode=work.mode,
        )
        session.add(atomic_event)
        session.flush()
        for entity in extracted.entities:
            _add_entity_mention(
                session,
                entity=entity,
                document_id=document_id,
                enrichment_id=int(enrichment.id),
                atomic_event_id=int(atomic_event.id),
                title=document.title_original,
                body=document.body_text,
            )
        for claim in extracted.claims:
            location = locate_evidence(
                document.title_original,
                document.body_text,
                claim.evidence.text,
            )
            session.add(
                ExtractedClaim(
                    atomic_event_id=atomic_event.id,
                    claim_type=claim.claim_type,
                    text=claim.text,
                    normalized_value=claim.normalized_value,
                    confidence=claim.confidence,
                    evidence_excerpt=claim.evidence.text,
                    evidence_field=location.field,
                    evidence_start=location.start,
                    evidence_end=location.end,
                )
            )

    work.status = "succeeded"
    work.lease_token = None
    work.lease_until = None
    work.next_retry_at = None
    work.error = None
    work.updated_at = datetime.now(UTC)
    session.flush()
    return int(enrichment.id)


def fail_document_work(
    session: Session,
    *,
    work_item_id: int,
    lease_token: str,
    error: str,
    retry_after_seconds: int,
    finish_reason: str | None = None,
    usage: dict | None = None,
) -> None:
    """Mark work retry (or terminal failed at max_attempts) with audit fields."""
    work = _locked_owned_work(session, work_item_id, lease_token)
    now = datetime.now(UTC)
    work.lease_token = None
    work.lease_until = None
    work.error = error[:2000]
    work.last_finish_reason = finish_reason
    if usage:
        work.last_usage = usage
    max_attempts = work.max_attempts or 5
    if (work.attempts or 0) >= max_attempts:
        work.status = "failed"  # terminal — no infinite retry
        work.next_retry_at = None
    else:
        work.status = "retry"
        work.next_retry_at = now + timedelta(seconds=retry_after_seconds)
    work.updated_at = now
    session.flush()
