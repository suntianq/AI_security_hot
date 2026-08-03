"""PostgreSQL-backed M2.1 local recomputation and event history service."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime
from itertools import batched
from typing import Any

from sqlalchemy import and_, delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, aliased

from ai_security_hot.domain.enums import NON_CURRENT_UPSTREAM_STATUSES, STRUCTURED_VULN_ENDPOINTS
from ai_security_hot.events.intelligence import (
    CLUSTER_VERSION,
    DEDUPE_VERSION,
    DedupDecision,
    EventDraft,
    IntelDocument,
    build_event_drafts,
    deduplicate_documents,
)
from ai_security_hot.events.signatures import (
    SIGNATURE_VERSION,
    DocumentSignatureDraft,
    assess_candidate,
    build_document_signature,
)
from ai_security_hot.models.tables import (
    CandidateReview,
    Claim,
    ClaimEvidence,
    Document,
    DocumentBlockToken,
    DocumentBlockTokenStat,
    DocumentIdentity,
    DocumentSignature,
    DuplicateComponent,
    Event,
    EventDocument,
    EventVersion,
    M2Run,
    M2WorkItem,
    RawItem,
    SourceEndpoint,
)

log = logging.getLogger("intel.event_repository")


def _current_alias_conditions(document) -> tuple:
    return (
        document.source_status == "active",
        document.record_status.not_in(NON_CURRENT_UPSTREAM_STATUSES),
    )


def _scope_conditions(document, scope: str) -> tuple:
    """Base current-document conditions plus the endpoint-scope filter.

    scope="all" (default) applies no endpoint restriction. scope="vuln" restricts
    to the structured-vulnerability endpoints (NVD/KEV); scope="general" excludes
    them so the news pipeline never touches the vuln-db corpus.
    """
    conditions = list(_current_alias_conditions(document))
    if scope == "vuln":
        conditions.append(document.endpoint_id.in_(STRUCTURED_VULN_ENDPOINTS))
    elif scope == "general":
        conditions.append(document.endpoint_id.notin_(STRUCTURED_VULN_ENDPOINTS))
    return tuple(conditions)


def _work_item_scope_condition(scope: str) -> tuple:
    """Document-scope filter for M2WorkItem claim queries.

    M2WorkItem rows do not carry a scope; the owning document's endpoint decides
    it. Without this filter a ``vuln`` pass would claim a general document's
    pending work item and merge it across the NVD/KEV isolation boundary (and a
    ``general`` pass could supersede vuln-db events). The filter is an IN
    subquery so rows with NULL document_id stay claimable only by an explicit
    scope="all" pass.
    """
    if scope == "vuln":
        return (
            M2WorkItem.document_id.in_(
                select(Document.id).where(
                    Document.endpoint_id.in_(STRUCTURED_VULN_ENDPOINTS)
                )
            ),
        )
    if scope == "general":
        return (
            M2WorkItem.document_id.in_(
                select(Document.id).where(
                    Document.endpoint_id.notin_(STRUCTURED_VULN_ENDPOINTS)
                )
            ),
        )
    return ()


def load_documents(
    session: Session,
    document_ids: set[int] | list[int] | tuple[int, ...],
    *,
    current_only: bool = True,
) -> list[IntelDocument]:
    if not document_ids:
        return []
    stmt = (
        select(
            Document.id,
            Document.endpoint_id,
            SourceEndpoint.source_id,
            SourceEndpoint.trust_tier,
            Document.title_original,
            Document.body_text,
            Document.canonical_url,
            Document.published_at_utc,
            RawItem.fetched_at,
            Document.identifiers,
            Document.tech_directions,
            Document.classified_event_type,
            Document.parse_quality,
            Document.entities,
            Document.company_models,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
        .where(Document.id.in_(document_ids))
        .order_by(Document.id)
    )
    if current_only:
        stmt = stmt.where(*_current_alias_conditions(Document))
    return [
        IntelDocument(
            id=int(row.id),
            endpoint_id=row.endpoint_id,
            source_id=row.source_id,
            trust_tier=row.trust_tier,
            title=row.title_original,
            body=row.body_text,
            canonical_url=row.canonical_url,
            published_at=row.published_at_utc,
            fetched_at=row.fetched_at,
            identifiers=row.identifiers or {},
            tech_directions=list(row.tech_directions or []),
            event_type=row.classified_event_type,
            parse_quality=row.parse_quality,
            content_length=len(row.body_text or ""),
            entities=row.entities or {},
            company_models=list(row.company_models or []),
        )
        for row in session.execute(stmt)
    ]


def count_signature_due(session: Session) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(Document)
            .outerjoin(DocumentSignature, DocumentSignature.document_id == Document.id)
            .where(
                *_current_alias_conditions(Document),
                (DocumentSignature.document_id.is_(None))
                | (DocumentSignature.signature_version != SIGNATURE_VERSION)
                | (DocumentSignature.active.is_(False)),
            )
        ).scalar_one()
    )


def signature_due_ids(session: Session, *, limit: int) -> list[int]:
    return [
        int(value)
        for value in session.execute(
            select(Document.id)
            .outerjoin(DocumentSignature, DocumentSignature.document_id == Document.id)
            .where(
                *_current_alias_conditions(Document),
                (DocumentSignature.document_id.is_(None))
                | (DocumentSignature.signature_version != SIGNATURE_VERSION)
                | (DocumentSignature.active.is_(False)),
            )
            .order_by(Document.id)
            .limit(limit)
        ).scalars()
    ]


def refresh_document_signatures(session: Session, document_ids: list[int] | set[int]) -> int:
    ids = sorted(set(document_ids))
    if not ids:
        return 0
    old_tokens = set(
        str(value)
        for value in session.execute(
            select(DocumentBlockToken.token).where(DocumentBlockToken.document_id.in_(ids))
        ).scalars()
    )
    current_docs = {document.id: document for document in load_documents(session, ids)}
    session.execute(delete(DocumentBlockToken).where(DocumentBlockToken.document_id.in_(ids)))
    session.execute(delete(DocumentIdentity).where(DocumentIdentity.document_id.in_(ids)))

    now = datetime.now(UTC)
    signature_rows: list[dict[str, Any]] = []
    token_rows: list[dict[str, Any]] = []
    identity_rows: list[dict[str, Any]] = []
    for document_id in ids:
        document = current_docs.get(document_id)
        if document is None:
            signature_rows.append(
                {
                    "document_id": document_id,
                    "signature_version": SIGNATURE_VERSION,
                    "url_hash": None,
                    "title_hash": None,
                    "content_hash": None,
                    "simhash": None,
                    "minhash": [],
                    "active": False,
                    "indexed_at": now,
                }
            )
            continue
        signature = build_document_signature(document)
        signature_rows.append(
            {
                "document_id": document_id,
                "signature_version": SIGNATURE_VERSION,
                "url_hash": signature.url_hash,
                "title_hash": signature.title_hash,
                "content_hash": signature.content_hash,
                "simhash": signature.simhash,
                "minhash": list(signature.minhash),
                "active": True,
                "indexed_at": now,
            }
        )
        token_rows.extend(
            {"document_id": document_id, "token": token[:96]} for token in signature.block_tokens
        )
        identity_rows.extend(
            {
                "document_id": document_id,
                "kind": identity.kind,
                "value": identity.value,
                "fingerprint": identity.fingerprint,
                "event_key": identity.event_key,
            }
            for identity in signature.identities
        )
    # PostgreSQL's extended protocol allows at most 65,535 parameters. One
    # configured batch can contain 20,000 signatures and hundreds of thousands
    # of derived rows, so every multi-row statement uses bounded chunks.
    for batch in batched(signature_rows, 5000, strict=False):
        insert = pg_insert(DocumentSignature).values(list(batch))
        session.execute(
            insert.on_conflict_do_update(
                index_elements=[DocumentSignature.document_id],
                set_={
                    "signature_version": insert.excluded.signature_version,
                    "url_hash": insert.excluded.url_hash,
                    "title_hash": insert.excluded.title_hash,
                    "content_hash": insert.excluded.content_hash,
                    "simhash": insert.excluded.simhash,
                    "minhash": insert.excluded.minhash,
                    "active": insert.excluded.active,
                    "indexed_at": insert.excluded.indexed_at,
                },
            )
        )
    for batch in batched(token_rows, 5000, strict=False):
        session.execute(pg_insert(DocumentBlockToken).values(list(batch)))
    for batch in batched(identity_rows, 5000, strict=False):
        session.execute(pg_insert(DocumentIdentity).values(list(batch)))
    _refresh_block_token_stats(
        session,
        old_tokens | {str(row["token"]) for row in token_rows},
    )
    return len(current_docs)


def _refresh_block_token_stats(session: Session, tokens: set[str]) -> None:
    now = datetime.now(UTC)
    for chunk in batched(sorted(tokens), 5000, strict=False):
        values = list(chunk)
        current_document = aliased(Document)
        counts = list(
            session.execute(
                select(DocumentBlockToken.token, func.count())
                .join(current_document, current_document.id == DocumentBlockToken.document_id)
                .where(
                    DocumentBlockToken.token.in_(values),
                    *_current_alias_conditions(current_document),
                )
                .group_by(DocumentBlockToken.token)
            )
        )
        session.execute(
            delete(DocumentBlockTokenStat).where(DocumentBlockTokenStat.token.in_(values))
        )
        if counts:
            session.execute(
                pg_insert(DocumentBlockTokenStat).values(
                    [
                        {
                            "token": str(token),
                            "active_document_count": int(count),
                            "updated_at": now,
                        }
                        for token, count in counts
                    ]
                )
            )


def rebuild_block_token_stats(session: Session) -> int:
    """Rebuild the bounded-candidate bucket counts from current evidence."""
    session.execute(delete(DocumentBlockTokenStat))
    current_document = aliased(Document)
    statement = pg_insert(DocumentBlockTokenStat).from_select(
        ["token", "active_document_count", "updated_at"],
        select(DocumentBlockToken.token, func.count(), func.now())
        .join(current_document, current_document.id == DocumentBlockToken.document_id)
        .where(*_current_alias_conditions(current_document))
        .group_by(DocumentBlockToken.token),
    )
    session.execute(statement)
    return int(
        session.execute(select(func.count()).select_from(DocumentBlockTokenStat)).scalar_one()
    )


def backfill_signature_batch(session: Session, *, limit: int = 5000) -> dict[str, int]:
    due_before = count_signature_due(session)
    ids = signature_due_ids(session, limit=limit)
    indexed = refresh_document_signatures(session, ids)
    return {
        "due_before": due_before,
        "indexed": indexed,
        "remaining": max(0, due_before - indexed),
    }


def enqueue_work(
    session: Session,
    document_ids: list[int] | set[int],
    *,
    stage: str,
    reason: str,
    algorithm_version: str,
    component_ids: dict[int, int | None] | None = None,
) -> int:
    rows = [
        {
            "document_id": document_id,
            "component_id": (component_ids or {}).get(document_id),
            "stage": stage,
            "reason": reason[:64],
            "algorithm_version": algorithm_version,
            "status": "pending",
        }
        for document_id in sorted(set(document_ids))
    ]
    if not rows:
        return 0
    insert = pg_insert(M2WorkItem).values(rows)
    result = session.execute(
        insert.on_conflict_do_nothing(
            index_elements=[M2WorkItem.document_id, M2WorkItem.stage],
            # PostgreSQL must prove this predicate is identical to the partial
            # unique index at plan time. A bound parameter cannot be matched to
            # ``WHERE status = 'pending'`` and raises InvalidColumnReference.
            index_where=text("status = 'pending'"),
        ).returning(M2WorkItem.id)
    )
    return len(list(result.scalars()))


def count_pending_work(session: Session, *, stage: str) -> int:
    """Count durable lifecycle work independently of document version flags."""
    return int(
        session.execute(
            select(func.count())
            .select_from(M2WorkItem)
            .where(M2WorkItem.stage == stage, M2WorkItem.status == "pending")
        ).scalar_one()
    )


def _claim_dedupe_seeds(
    session: Session, *, limit: int, run_id: int, scope: str = "all"
) -> tuple[list[int], list[int], set[int]]:
    now = datetime.now(UTC)
    work = list(
        session.execute(
            select(M2WorkItem)
            .where(
                M2WorkItem.stage == "dedupe",
                M2WorkItem.status == "pending",
                *_work_item_scope_condition(scope),
            )
            .order_by(M2WorkItem.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    work_document_ids = {int(item.document_id) for item in work if item.document_id is not None}
    seed_ids = list(work_document_ids)
    remaining = max(0, limit - len(set(seed_ids)))
    if remaining:
        due_stmt = select(Document.id).where(
            *_scope_conditions(Document, scope),
            (Document.dedupe_version.is_(None)) | (Document.dedupe_version != DEDUPE_VERSION),
        )
        if seed_ids:
            due_stmt = due_stmt.where(~Document.id.in_(seed_ids))
        due_ids = list(session.execute(due_stmt.order_by(Document.id).limit(remaining)).scalars())
        seed_ids.extend(int(value) for value in due_ids)
    for item in work:
        item.status = "processing"
        item.claimed_at = now
        item.run_id = run_id
    return sorted(set(seed_ids)), [int(item.id) for item in work], work_document_ids


def _candidate_pairs(
    session: Session,
    seed_ids: list[int],
    *,
    max_pairs: int,
    excluded_candidate_ids: set[int] | None = None,
    scope: str = "all",
) -> tuple[list[tuple[int, int]], bool]:
    if not seed_ids:
        return [], False
    pairs: set[tuple[int, int]] = set()
    excluded = sorted(excluded_candidate_ids or set())
    review_candidate = aliased(Document)
    approved_left_stmt = (
        select(CandidateReview.left_document_id, CandidateReview.right_document_id)
        .join(review_candidate, review_candidate.id == CandidateReview.right_document_id)
        .where(
            CandidateReview.left_document_id.in_(seed_ids),
            CandidateReview.status == "approved",
            CandidateReview.algorithm_version == DEDUPE_VERSION,
            *_scope_conditions(review_candidate, scope),
        )
        .distinct()
        .order_by(CandidateReview.left_document_id, CandidateReview.right_document_id)
        .limit(max_pairs + 1)
    )
    if excluded:
        approved_left_stmt = approved_left_stmt.where(
            CandidateReview.right_document_id.not_in(excluded)
        )
    approved_left_rows = list(session.execute(approved_left_stmt))

    review_candidate = aliased(Document)
    approved_right_stmt = (
        select(CandidateReview.right_document_id, CandidateReview.left_document_id)
        .join(review_candidate, review_candidate.id == CandidateReview.left_document_id)
        .where(
            CandidateReview.right_document_id.in_(seed_ids),
            CandidateReview.status == "approved",
            CandidateReview.algorithm_version == DEDUPE_VERSION,
            *_scope_conditions(review_candidate, scope),
        )
        .distinct()
        .order_by(CandidateReview.right_document_id, CandidateReview.left_document_id)
        .limit(max_pairs + 1)
    )
    if excluded:
        approved_right_stmt = approved_right_stmt.where(
            CandidateReview.left_document_id.not_in(excluded)
        )
    approved_right_rows = list(session.execute(approved_right_stmt))
    for left, right in (*approved_left_rows, *approved_right_rows):
        pairs.add((min(int(left), int(right)), max(int(left), int(right))))
    if (
        len(approved_left_rows) > max_pairs
        or len(approved_right_rows) > max_pairs
        or len(pairs) > max_pairs
    ):
        return sorted(pairs)[:max_pairs], True

    for field in ("url_hash", "title_hash", "content_hash"):
        seed_sig = aliased(DocumentSignature)
        candidate_sig = aliased(DocumentSignature)
        candidate_doc = aliased(Document)
        signature_column = getattr(DocumentSignature, field)
        seed_column = getattr(seed_sig, field)
        candidate_column = getattr(candidate_sig, field)
        frequency_signature = aliased(DocumentSignature)
        frequency_document = aliased(Document)
        frequency_column = getattr(frequency_signature, field)
        seed_values = (
            select(signature_column)
            .where(
                DocumentSignature.document_id.in_(seed_ids),
                signature_column.is_not(None),
            )
            .distinct()
        )
        bounded_values = (
            select(frequency_column.label("value"))
            .join(
                frequency_document,
                frequency_document.id == frequency_signature.document_id,
            )
            .where(
                frequency_signature.active.is_(True),
                frequency_column.in_(seed_values),
                *_scope_conditions(frequency_document, scope),
            )
            .group_by(frequency_column)
            .having(func.count() <= 100)
            .subquery()
        )
        exact_stmt = (
            select(seed_sig.document_id, candidate_sig.document_id)
            .join(candidate_sig, seed_column == candidate_column)
            .join(bounded_values, bounded_values.c.value == seed_column)
            .join(candidate_doc, candidate_doc.id == candidate_sig.document_id)
            .where(
                seed_sig.document_id.in_(seed_ids),
                seed_column.is_not(None),
                candidate_sig.active.is_(True),
                seed_sig.document_id != candidate_sig.document_id,
                *_scope_conditions(candidate_doc, scope),
            )
            .distinct()
            .order_by(seed_sig.document_id, candidate_sig.document_id)
            .limit(max_pairs + 1)
        )
        if excluded:
            exact_stmt = exact_stmt.where(candidate_sig.document_id.not_in(excluded))
        exact_rows = list(session.execute(exact_stmt))
        for left, right in exact_rows:
            pairs.add((min(int(left), int(right)), max(int(left), int(right))))
        if len(exact_rows) > max_pairs or len(pairs) > max_pairs:
            return sorted(pairs)[:max_pairs], True

    def token_candidate_base(candidate_seed_ids: list[int], *, lsh: bool):
        seed_token = aliased(DocumentBlockToken)
        candidate_token = aliased(DocumentBlockToken)
        seed_document = aliased(Document)
        candidate_doc = aliased(Document)
        token_filters = (
            (or_(seed_token.token.like("sim:%"), seed_token.token.like("min:%")),)
            if lsh
            else (seed_token.token.not_like("sim:%"), seed_token.token.not_like("min:%"))
        )
        token_stat = aliased(DocumentBlockTokenStat)
        time_compatible = or_(
            seed_document.published_at_utc.is_(None),
            candidate_doc.published_at_utc.is_(None),
            func.abs(
                func.extract(
                    "epoch",
                    seed_document.published_at_utc - candidate_doc.published_at_utc,
                )
            )
            <= 30 * 86400,
        )
        statement = (
            select(seed_token.document_id, candidate_token.document_id)
            .join(token_stat, token_stat.token == seed_token.token)
            .join(candidate_token, candidate_token.token == seed_token.token)
            .join(seed_document, seed_document.id == seed_token.document_id)
            .join(candidate_doc, candidate_doc.id == candidate_token.document_id)
            .where(
                seed_token.document_id.in_(candidate_seed_ids),
                *token_filters,
                token_stat.active_document_count <= 100,
                seed_token.document_id != candidate_token.document_id,
                time_compatible,
                *_scope_conditions(candidate_doc, scope),
            )
        )
        if excluded:
            statement = statement.where(candidate_token.document_id.not_in(excluded))
        return statement, seed_token, candidate_token

    lsh_base, lsh_seed_token, lsh_candidate_token = token_candidate_base(seed_ids, lsh=True)
    lsh_stmt = (
        lsh_base.distinct()
        .order_by(lsh_seed_token.document_id, lsh_candidate_token.document_id)
        .limit(max_pairs + 1)
    )
    lsh_rows = list(session.execute(lsh_stmt))
    for left, right in lsh_rows:
        pairs.add((min(int(left), int(right)), max(int(left), int(right))))
    if len(lsh_rows) > max_pairs or len(pairs) > max_pairs:
        return sorted(pairs)[:max_pairs], True

    for seed_chunk in batched(seed_ids, 20, strict=False):
        lexical_base, lexical_seed_token, _lexical_candidate_token = token_candidate_base(
            list(seed_chunk), lsh=False
        )
        shared_counts: dict[tuple[int, int], int] = defaultdict(int)
        for left, right, _token in session.execute(
            lexical_base.add_columns(lexical_seed_token.token)
        ):
            shared_counts[(int(left), int(right))] += 1
        for (left, right), shared_count in shared_counts.items():
            if shared_count >= 2:
                pairs.add((min(left, right), max(left, right)))
        if len(pairs) > max_pairs:
            return sorted(pairs)[:max_pairs], True
    return sorted(pairs), False


def _expand_component_closure(
    session: Session, document_ids: set[int], *, max_documents: int, scope: str = "all"
) -> set[int]:
    if not document_ids:
        return set()
    if len(document_ids) > max_documents:
        raise RuntimeError(f"local dedupe seed set exceeds limit {max_documents}")
    component_ids = set(
        int(value)
        for value in session.execute(
            select(Document.dedupe_component_id).where(
                Document.id.in_(document_ids), Document.dedupe_component_id.is_not(None)
            )
        ).scalars()
        if value is not None
    )
    if not component_ids:
        return document_ids
    members = set(
        int(value)
        for value in session.execute(
            select(Document.id)
            .where(
                Document.dedupe_component_id.in_(component_ids),
                *_scope_conditions(Document, scope),
            )
            .order_by(Document.id)
            .limit(max_documents + 1)
        ).scalars()
    )
    if len(members | document_ids) > max_documents:
        raise RuntimeError(
            f"local dedupe closure exceeds limit {max_documents}; run an explicit bounded replay"
        )
    return members | document_ids


def _expand_dedupe_closure(
    session: Session,
    seed_ids: set[int],
    *,
    max_documents: int,
    max_pairs: int,
    scope: str = "all",
) -> tuple[set[int], list[tuple[int, int]]]:
    """Load seed components, one-hop candidates and every candidate's old component.

    Weak LSH/token edges are deliberately not traversed recursively: doing so
    turns a large similarity graph into one global connected component. An
    unchanged candidate's other possible relationships are handled by its own
    version work; its established duplicate component is included immediately.
    """
    seed_universe = _expand_component_closure(
        session, set(seed_ids), max_documents=max_documents, scope=scope
    )
    pairs, truncated = _candidate_pairs(
        session,
        sorted(seed_universe),
        max_pairs=max_pairs,
        scope=scope,
    )
    if truncated:
        raise RuntimeError(f"local dedupe candidate graph exceeds pair limit {max_pairs}")
    candidate_ids = {document_id for pair in pairs for document_id in pair}
    universe = _expand_component_closure(
        session,
        seed_universe | candidate_ids,
        max_documents=max_documents,
        scope=scope,
    )
    return universe, pairs


def _persist_reviews(
    session: Session,
    pairs: list[tuple[int, int]],
    documents: dict[int, IntelDocument],
) -> int:
    candidate_ids = {document_id for pair in pairs for document_id in pair}
    signatures = {
        int(row.document_id): DocumentSignatureDraft(
            url_hash=row.url_hash,
            title_hash=row.title_hash,
            content_hash=row.content_hash,
            simhash=row.simhash,
            minhash=tuple(int(value) for value in (row.minhash or [])),
            block_tokens=(),
            identities=(),
        )
        for row in session.execute(
            select(DocumentSignature).where(DocumentSignature.document_id.in_(candidate_ids))
        ).scalars()
    }
    rows: list[dict[str, Any]] = []
    for left_id, right_id in pairs:
        left = documents.get(left_id)
        right = documents.get(right_id)
        if left is None or right is None:
            continue
        assessment = assess_candidate(
            left,
            right,
            left_signature=signatures.get(left_id),
            right_signature=signatures.get(right_id),
        )
        if assessment.decision not in {"review", "separate"} or (
            assessment.decision == "separate" and not assessment.conflict
        ):
            continue
        rows.append(
            {
                "left_document_id": left_id,
                "right_document_id": right_id,
                "candidate_kind": assessment.reason,
                "score": assessment.score,
                "features": {
                    "title_score": assessment.title_score,
                    "simhash_distance": assessment.simhash_distance,
                    "minhash_similarity": assessment.minhash_similarity,
                },
                "conflict_reason": assessment.conflict,
                "status": "rejected" if assessment.conflict else "pending",
                "algorithm_version": DEDUPE_VERSION,
            }
        )
    if not rows:
        return 0
    inserted = 0
    for batch in batched(rows, 5000, strict=False):
        result = session.execute(
            pg_insert(CandidateReview)
            .values(list(batch))
            .on_conflict_do_nothing(constraint="uq_candidate_review_pair_version")
            .returning(CandidateReview.id)
        )
        inserted += len(list(result.scalars()))
    return inserted


def list_candidate_reviews(
    session: Session, *, status: str = "pending", limit: int = 50
) -> list[dict[str, Any]]:
    left_document = aliased(Document)
    right_document = aliased(Document)
    rows = session.execute(
        select(
            CandidateReview,
            left_document.title_original.label("left_title"),
            right_document.title_original.label("right_title"),
        )
        .join(left_document, left_document.id == CandidateReview.left_document_id)
        .join(right_document, right_document.id == CandidateReview.right_document_id)
        .where(CandidateReview.status == status)
        .order_by(CandidateReview.score.desc(), CandidateReview.id)
        .limit(limit)
    )
    return [
        {
            "id": int(review.id),
            "left_document_id": int(review.left_document_id),
            "left_title": row.left_title,
            "right_document_id": int(review.right_document_id),
            "right_title": row.right_title,
            "candidate_kind": review.candidate_kind,
            "score": review.score,
            "features": review.features,
            "conflict_reason": review.conflict_reason,
            "status": review.status,
            "algorithm_version": review.algorithm_version,
            "reviewer": review.reviewer,
            "notes": review.notes,
        }
        for row in rows
        for review in [row[0]]
    ]


def resolve_candidate_review(
    session: Session,
    review_id: int,
    *,
    decision: str,
    reviewer: str,
    notes: str | None = None,
) -> dict[str, Any]:
    if decision not in {"approved", "rejected"}:
        raise ValueError("decision must be approved or rejected")
    if not reviewer.strip():
        raise ValueError("reviewer is required")
    review = session.execute(
        select(CandidateReview).where(CandidateReview.id == review_id).with_for_update()
    ).scalar_one_or_none()
    if review is None:
        raise KeyError(f"candidate review not found: {review_id}")
    documents = {
        document.id: document
        for document in load_documents(
            session,
            {review.left_document_id, review.right_document_id},
            current_only=False,
        )
    }
    left = documents.get(review.left_document_id)
    right = documents.get(review.right_document_id)
    if decision == "approved":
        if review.conflict_reason:
            raise ValueError(
                f"strong identity conflict cannot be approved: {review.conflict_reason}"
            )
        if left is None or right is None:
            raise ValueError("both reviewed documents must still exist")
        conflict = assess_candidate(left, right).conflict
        if conflict:
            raise ValueError(f"strong identity conflict cannot be approved: {conflict}")
    review.status = decision
    review.reviewer = reviewer.strip()[:128]
    review.notes = notes
    review.reviewed_at = datetime.now(UTC)
    document_ids = {int(review.left_document_id), int(review.right_document_id)}
    components = {
        int(document_id): int(component_id) if component_id is not None else None
        for document_id, component_id in session.execute(
            select(Document.id, Document.dedupe_component_id).where(Document.id.in_(document_ids))
        )
    }
    enqueue_work(
        session,
        document_ids,
        stage="dedupe",
        reason="candidate_review",
        algorithm_version=DEDUPE_VERSION,
        component_ids=components,
    )
    enqueue_work(
        session,
        document_ids,
        stage="cluster",
        reason="candidate_review",
        algorithm_version=CLUSTER_VERSION,
        component_ids=components,
    )
    return {
        "id": int(review.id),
        "status": review.status,
        "left_document_id": int(review.left_document_id),
        "right_document_id": int(review.right_document_id),
        "queued": True,
    }


def _approved_pairs(session: Session, document_ids: set[int]) -> set[tuple[int, int]]:
    if not document_ids:
        return set()
    return {
        (int(left), int(right))
        for left, right in session.execute(
            select(CandidateReview.left_document_id, CandidateReview.right_document_id).where(
                CandidateReview.status == "approved",
                CandidateReview.algorithm_version == DEDUPE_VERSION,
                CandidateReview.left_document_id.in_(document_ids),
                CandidateReview.right_document_id.in_(document_ids),
            )
        )
    }


def _assign_components(
    session: Session,
    documents: dict[int, IntelDocument],
    decisions: dict[int, DedupDecision],
) -> dict[int, int]:
    document_ids = sorted(documents)
    old_component_by_doc = {
        int(document_id): int(component_id)
        for document_id, component_id in session.execute(
            select(Document.id, Document.dedupe_component_id).where(
                Document.id.in_(document_ids), Document.dedupe_component_id.is_not(None)
            )
        )
    }
    old_component_ids = set(old_component_by_doc.values())
    old_master_by_component = {
        int(component_id): int(master_id) if master_id is not None else None
        for component_id, master_id in session.execute(
            select(DuplicateComponent.id, DuplicateComponent.master_document_id).where(
                DuplicateComponent.id.in_(old_component_ids)
            )
        )
    }
    groups: dict[int, set[int]] = defaultdict(set)
    for document_id, decision in decisions.items():
        groups[decision.near_dup_of or document_id].add(document_id)

    assigned: dict[int, int] = {}
    used_components: set[int] = set()
    # A split keeps the stable component ID on the group containing its former
    # master. All other fragments get fresh IDs.
    ordered_groups = sorted(groups.items(), key=lambda item: item[0])
    for new_master, members in ordered_groups:
        old_candidates = sorted(
            {old_component_by_doc[member] for member in members if member in old_component_by_doc}
        )
        preferred = next(
            (
                component_id
                for component_id in old_candidates
                if old_master_by_component.get(component_id) in members
                and component_id not in used_components
            ),
            None,
        )
        component_id = preferred or next(
            (value for value in old_candidates if value not in used_components), None
        )
        if component_id is None:
            component = DuplicateComponent(
                master_document_id=new_master,
                algorithm_version=DEDUPE_VERSION,
                updated_at=datetime.now(UTC),
            )
            session.add(component)
            session.flush()
            component_id = int(component.id)
        else:
            session.execute(
                update(DuplicateComponent)
                .where(DuplicateComponent.id == component_id)
                .values(
                    master_document_id=new_master,
                    algorithm_version=DEDUPE_VERSION,
                    updated_at=datetime.now(UTC),
                )
            )
        used_components.add(component_id)
        assigned.update({member: component_id for member in members})
    stale_component_ids = old_component_ids - used_components
    if stale_component_ids:
        session.execute(
            update(DuplicateComponent)
            .where(DuplicateComponent.id.in_(stale_component_ids))
            .values(master_document_id=None, updated_at=datetime.now(UTC))
        )
    return assigned


def _persist_local_decisions(
    session: Session,
    decisions: dict[int, DedupDecision],
    components: dict[int, int],
) -> int:
    now = datetime.now(UTC)
    updated = 0
    for document_id, decision in decisions.items():
        row = session.get(Document, document_id)
        if row is None:
            continue
        desired = (
            decision.near_dup_of,
            decision.duplicate_kind,
            decision.duplicate_score,
            components[document_id],
            DEDUPE_VERSION,
        )
        current = (
            row.near_dup_of,
            row.duplicate_kind,
            row.duplicate_score,
            row.dedupe_component_id,
            row.dedupe_version,
        )
        row.near_dup_of = decision.near_dup_of
        row.duplicate_kind = decision.duplicate_kind
        row.duplicate_score = decision.duplicate_score
        row.dedupe_component_id = components[document_id]
        row.dedupe_version = DEDUPE_VERSION
        row.deduped_at = now
        if current != desired:
            row.cluster_version = None
            row.clustered_at = None
            updated += 1
    return updated


def run_local_dedupe(
    session: Session,
    *,
    limit: int = 1000,
    max_candidates: int = 20000,
    trigger: str = "scheduler",
    scope: str = "all",
) -> dict[str, Any]:
    run = M2Run(
        stage="dedupe",
        mode="replay" if trigger == "replay" else "incremental",
        algorithm_version=DEDUPE_VERSION,
        trigger=trigger,
        status="running",
    )
    session.add(run)
    session.flush()
    seed_ids, work_ids, changed_seed_ids = _claim_dedupe_seeds(
        session, limit=limit, run_id=int(run.id), scope=scope
    )
    if not seed_ids:
        run.status = "success"
        run.finished_at = datetime.now(UTC)
        run.stats = {"status": "current", "scope": scope}
        return {"status": "current", "version": DEDUPE_VERSION, "due": 0, "run_id": run.id}

    # Signature backfill runs before this stage. Pure algorithm-version replay
    # seeds can reuse that persisted index; only durable content/classification/
    # lifecycle work may have changed the signature since it was indexed.
    refresh_document_signatures(session, changed_seed_ids)
    # Dense scopes (e.g. NVD/KEV) can exceed the candidate pair budget. Instead
    # of aborting the whole batch, retry on a progressively smaller seed slice.
    batch_seeds = seed_ids
    universe_ids: set[int] = set()
    pairs: list[tuple[int, int]] = []
    while batch_seeds:
        try:
            universe_ids, pairs = _expand_dedupe_closure(
                session,
                set(batch_seeds),
                max_documents=max_candidates,
                max_pairs=max_candidates,
                scope=scope,
            )
            break
        except RuntimeError as exc:
            if "candidate graph exceeds pair limit" not in str(exc):
                raise
            if len(batch_seeds) <= 1:
                raise
            halved = batch_seeds[: max(1, len(batch_seeds) // 2)]
            log.warning(
                "dedupe candidate graph exceeded pair limit for %d seeds; "
                "retrying on %d seeds",
                len(batch_seeds),
                len(halved),
            )
            batch_seeds = halved
    documents = {document.id: document for document in load_documents(session, universe_ids)}
    decisions = deduplicate_documents(
        list(documents.values()),
        approved_pairs=_approved_pairs(session, set(documents)),
    )
    review_count = _persist_reviews(session, pairs, documents)
    component_ids = _assign_components(session, documents, decisions)
    updated = _persist_local_decisions(session, decisions, component_ids)
    if work_ids:
        session.execute(
            update(M2WorkItem)
            .where(M2WorkItem.id.in_(work_ids))
            .values(status="done", completed_at=datetime.now(UTC))
        )
    stats = {
        "seeds": len(seed_ids),
        "candidates": len(pairs),
        "affected_documents": len(documents),
        "components": len(set(component_ids.values())),
        "updated": updated,
        "duplicates": sum(decision.near_dup_of is not None for decision in decisions.values()),
        "reviews_created": review_count,
    }
    run.status = "success"
    run.input_count = len(seed_ids)
    run.candidate_count = len(pairs)
    run.affected_count = len(documents)
    run.stats = stats
    run.finished_at = datetime.now(UTC)
    return {
        "status": "ok",
        "version": DEDUPE_VERSION,
        "due": len(seed_ids),
        "run_id": run.id,
        **stats,
    }


def _claim_cluster_seeds(
    session: Session, *, limit: int, run_id: int, scope: str = "all"
) -> tuple[list[int], set[int], list[int]]:
    now = datetime.now(UTC)
    work = list(
        session.execute(
            select(M2WorkItem)
            .where(
                M2WorkItem.stage == "cluster",
                M2WorkItem.status == "pending",
                *_work_item_scope_condition(scope),
            )
            .order_by(M2WorkItem.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    seed_ids = [int(item.document_id) for item in work if item.document_id is not None]
    component_ids = {int(item.component_id) for item in work if item.component_id is not None}
    remaining = max(0, limit - len(set(seed_ids)))
    if remaining:
        due_stmt = select(Document.id).where(
            *_scope_conditions(Document, scope),
            Document.dedupe_version == DEDUPE_VERSION,
            (Document.cluster_version.is_(None)) | (Document.cluster_version != CLUSTER_VERSION),
        )
        if seed_ids:
            due_stmt = due_stmt.where(~Document.id.in_(seed_ids))
        due_ids = list(session.execute(due_stmt.order_by(Document.id).limit(remaining)).scalars())
        seed_ids.extend(int(value) for value in due_ids)
    component_ids.update(
        int(value)
        for value in session.execute(
            select(Document.dedupe_component_id).where(
                Document.id.in_(seed_ids), Document.dedupe_component_id.is_not(None)
            )
        ).scalars()
        if value is not None
    )
    for item in work:
        item.status = "processing"
        item.claimed_at = now
        item.run_id = run_id
    return sorted(set(seed_ids)), component_ids, [int(item.id) for item in work]


def _component_document_ids(
    session: Session, component_ids: set[int], *, max_documents: int, scope: str = "all"
) -> set[int]:
    if not component_ids:
        return set()
    ids = set(
        int(value)
        for value in session.execute(
            select(Document.id)
            .where(
                Document.dedupe_component_id.in_(component_ids),
                Document.dedupe_version == DEDUPE_VERSION,
                *_scope_conditions(Document, scope),
            )
            .order_by(Document.id)
            .limit(max_documents + 1)
        ).scalars()
    )
    if len(ids) > max_documents:
        raise RuntimeError(f"local cluster component closure exceeds limit {max_documents}")
    return ids


def _expand_event_closure(
    session: Session,
    component_ids: set[int],
    *,
    max_documents: int,
    scope: str = "all",
) -> tuple[set[int], set[str]]:
    """Expand through event-key identities until the affected graph is closed."""
    active_components = set(component_ids)
    document_ids: set[int] = set()
    event_identity_fingerprints: set[str] = set()
    while True:
        document_ids = _component_document_ids(
            session, active_components, max_documents=max_documents, scope=scope
        )
        if not document_ids:
            return set(), set()
        identity_rows = list(
            session.execute(
                select(DocumentIdentity.kind, DocumentIdentity.fingerprint)
                .where(
                    DocumentIdentity.document_id.in_(document_ids),
                    DocumentIdentity.event_key.is_(True),
                )
                .distinct()
            )
        )
        identities_by_kind: dict[str, set[str]] = defaultdict(set)
        for row in identity_rows:
            identities_by_kind[str(row.kind)].add(str(row.fingerprint))
        event_identity_fingerprints = {
            fingerprint
            for fingerprints in identities_by_kind.values()
            for fingerprint in fingerprints
        }
        if not event_identity_fingerprints:
            return document_ids, set()
        # The reverse index is ordered by (kind, fingerprint, document_id).
        # Keeping kind in the predicate prevents every local event rebuild from
        # scanning the full identity table as the corpus grows.
        identity_filters = [
            and_(
                DocumentIdentity.kind == kind,
                DocumentIdentity.fingerprint.in_(sorted(fingerprints)),
            )
            for kind, fingerprints in sorted(identities_by_kind.items())
        ]
        matching_ids = set(
            int(value)
            for value in session.execute(
                select(DocumentIdentity.document_id)
                .join(Document, Document.id == DocumentIdentity.document_id)
                .where(
                    DocumentIdentity.event_key.is_(True),
                    or_(*identity_filters),
                    *_scope_conditions(Document, scope),
                )
                .distinct()
                .limit(max_documents + 1)
            ).scalars()
            if value is not None
        )
        matching_components = set(
            int(value)
            for value in session.execute(
                select(Document.dedupe_component_id).where(
                    Document.id.in_(matching_ids),
                    Document.dedupe_component_id.is_not(None),
                )
            ).scalars()
            if value is not None
        )
        expanded = active_components | matching_components
        if expanded == active_components:
            return document_ids, event_identity_fingerprints
        if len(matching_ids | document_ids) > max_documents:
            raise RuntimeError(f"local event closure exceeds limit {max_documents}")
        active_components = expanded


def _load_decisions(session: Session, document_ids: set[int]) -> dict[int, DedupDecision]:
    return {
        int(row.id): DedupDecision(
            int(row.id), row.near_dup_of, row.duplicate_kind, row.duplicate_score
        )
        for row in session.execute(
            select(
                Document.id,
                Document.near_dup_of,
                Document.duplicate_kind,
                Document.duplicate_score,
            ).where(Document.id.in_(document_ids))
        )
    }


def _claim_snapshot_from_rows(
    claims: list[Claim],
    evidence_by_claim: dict[int, list[ClaimEvidence]],
) -> list[dict[str, Any]]:
    return [
        {
            "claim_key": claim.claim_key,
            "claim_type": claim.claim_type,
            "text": claim.text,
            "normalized_value": claim.normalized_value,
            "status": claim.status,
            "confidence": claim.confidence,
            "evidence": [
                {
                    "document_id": int(evidence.document_id),
                    "stance": evidence.stance,
                    "evidence_level": evidence.evidence_level,
                    "excerpt": evidence.excerpt,
                }
                for evidence in sorted(
                    evidence_by_claim.get(int(claim.id), []),
                    key=lambda row: (int(row.document_id), row.stance),
                )
            ],
        }
        for claim in sorted(claims, key=lambda row: row.claim_key)
    ]


def _claim_snapshot(session: Session, event_id: int) -> list[dict[str, Any]]:
    claims = list(session.execute(select(Claim).where(Claim.event_id == event_id)).scalars())
    claim_ids = [int(claim.id) for claim in claims]
    evidence_by_claim: dict[int, list[ClaimEvidence]] = defaultdict(list)
    if claim_ids:
        for evidence in session.execute(
            select(ClaimEvidence).where(ClaimEvidence.claim_id.in_(claim_ids))
        ).scalars():
            evidence_by_claim[int(evidence.claim_id)].append(evidence)
    return _claim_snapshot_from_rows(claims, evidence_by_claim)


def _snapshot_payload(
    event: Event,
    links: dict[int, tuple[str | None, str | None]],
    claims: list[dict[str, Any]],
) -> dict:
    return {
        "id": int(event.id),
        "fingerprint": event.fingerprint,
        "event_type": event.event_type,
        "topic": event.topic,
        "title": event.title,
        "summary": event.summary,
        "status": event.status,
        "score": event.score,
        "evidence_level": event.evidence_level,
        "cluster_version": event.cluster_version,
        "first_seen_at": event.first_seen_at.isoformat() if event.first_seen_at else None,
        "last_seen_at": event.last_seen_at.isoformat() if event.last_seen_at else None,
        "evidence": [
            {
                "document_id": document_id,
                "evidence_level": values[0],
                "relation_reason": values[1],
            }
            for document_id, values in sorted(links.items())
        ],
        "claims": claims,
    }


def _snapshot_diff(before: dict | None, after: dict) -> dict:
    if before is None:
        return {"created": True, "fields": sorted(after)}
    changed = sorted(key for key in after if before.get(key) != after.get(key))
    before_ids = {row["document_id"] for row in before.get("evidence", [])}
    after_ids = {row["document_id"] for row in after.get("evidence", [])}
    before_claims = {row["claim_key"]: row for row in before.get("claims", [])}
    after_claims = {row["claim_key"]: row for row in after.get("claims", [])}
    return {
        "changed_fields": changed,
        "evidence_added": sorted(after_ids - before_ids),
        "evidence_removed": sorted(before_ids - after_ids),
        "claims_added": sorted(after_claims.keys() - before_claims.keys()),
        "claims_removed": sorted(before_claims.keys() - after_claims.keys()),
        "claims_changed": sorted(
            key
            for key in before_claims.keys() & after_claims.keys()
            if before_claims[key] != after_claims[key]
        ),
    }


def _claim_key(value: str) -> str:
    if len(value) <= 160:
        return value
    import hashlib

    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _sync_claims(
    session: Session,
    event: Event,
    links: dict[int, tuple[str | None, str | None]],
    *,
    existing: dict[str, Claim] | None = None,
    evidence_by_claim: dict[int, list[ClaimEvidence]] | None = None,
) -> list[dict[str, Any]]:
    identity_kind, _, identity_value = event.fingerprint.partition(":")
    desired = [
        {
            "claim_key": _claim_key("summary:event"),
            "claim_type": "event_summary",
            "text": event.summary or event.title,
            "normalized_value": {"title": event.title},
            "status": "unverified",
            "confidence": None,
        }
    ]
    if identity_kind != "document" and identity_value:
        desired.append(
            {
                "claim_key": _claim_key(f"identity:{event.fingerprint}"),
                "claim_type": "identity",
                "text": f"Stable event identity: {event.fingerprint}",
                "normalized_value": {
                    "kind": identity_kind,
                    "value": identity_value,
                    "fingerprint": event.fingerprint,
                },
                "status": "confirmed",
                "confidence": 1.0,
            }
        )
    desired_keys = {row["claim_key"] for row in desired}
    if existing is None:
        existing = {
            claim.claim_key: claim
            for claim in session.execute(select(Claim).where(Claim.event_id == event.id)).scalars()
        }
    if evidence_by_claim is None:
        evidence_by_claim = defaultdict(list)
        claim_ids = [int(claim.id) for claim in existing.values()]
        if claim_ids:
            for evidence in session.execute(
                select(ClaimEvidence).where(ClaimEvidence.claim_id.in_(claim_ids))
            ).scalars():
                evidence_by_claim[int(evidence.claim_id)].append(evidence)
    for row in desired:
        claim = existing.get(row["claim_key"])
        if claim is None:
            claim = Claim(event_id=event.id, **row)
            session.add(claim)
            session.flush()
            existing[claim.claim_key] = claim
        else:
            claim.claim_type = row["claim_type"]
            claim.text = row["text"]
            claim.normalized_value = row["normalized_value"]
            # Manual disputed/rejected states are authoritative and never
            # overwritten by deterministic refreshes.
            if claim.status in {"unverified", "confirmed"}:
                claim.status = row["status"]
                claim.confidence = row["confidence"]
            claim.updated_at = datetime.now(UTC)
        old_evidence = {
            evidence.document_id: evidence for evidence in evidence_by_claim.get(int(claim.id), [])
        }
        stale_ids = set(old_evidence) - set(links)
        if stale_ids:
            session.execute(
                delete(ClaimEvidence).where(
                    ClaimEvidence.claim_id == claim.id,
                    ClaimEvidence.document_id.in_(stale_ids),
                )
            )
            evidence_by_claim[int(claim.id)] = [
                evidence
                for evidence in evidence_by_claim.get(int(claim.id), [])
                if evidence.document_id not in stale_ids
            ]
        for document_id, (level, _reason) in links.items():
            evidence = old_evidence.get(document_id)
            if evidence is None:
                evidence = ClaimEvidence(
                    claim_id=claim.id,
                    document_id=document_id,
                    stance="support",
                    evidence_level=level,
                )
                session.add(evidence)
                evidence_by_claim.setdefault(int(claim.id), []).append(evidence)
            else:
                evidence.evidence_level = level
    # Obsolete auto claims are retained for correction history, but no longer
    # receive current evidence. Manually authored claims are untouched.
    obsolete_ids = [
        claim.id
        for key, claim in existing.items()
        if key not in desired_keys and claim.claim_type in {"identity", "event_summary"}
    ]
    if obsolete_ids:
        session.execute(delete(ClaimEvidence).where(ClaimEvidence.claim_id.in_(obsolete_ids)))
        for claim_id in obsolete_ids:
            evidence_by_claim[int(claim_id)] = []
    return _claim_snapshot_from_rows(list(existing.values()), evidence_by_claim)


def _load_event_batch_state(
    session: Session,
    fingerprints: set[str],
) -> tuple[
    dict[str, Event],
    dict[int, dict[int, EventDocument]],
    dict[int, dict[str, Claim]],
    dict[int, list[ClaimEvidence]],
]:
    events = list(
        session.execute(
            select(Event).where(Event.fingerprint.in_(fingerprints)).with_for_update()
        ).scalars()
    )
    events_by_fingerprint = {event.fingerprint: event for event in events}
    event_ids = [int(event.id) for event in events]
    links_by_event: dict[int, dict[int, EventDocument]] = defaultdict(dict)
    claims_by_event: dict[int, dict[str, Claim]] = defaultdict(dict)
    evidence_by_claim: dict[int, list[ClaimEvidence]] = defaultdict(list)
    if not event_ids:
        return events_by_fingerprint, links_by_event, claims_by_event, evidence_by_claim
    for link in session.execute(
        select(EventDocument).where(EventDocument.event_id.in_(event_ids))
    ).scalars():
        links_by_event[int(link.event_id)][int(link.document_id)] = link
    claims = list(session.execute(select(Claim).where(Claim.event_id.in_(event_ids))).scalars())
    for claim in claims:
        claims_by_event[int(claim.event_id)][claim.claim_key] = claim
    claim_ids = [int(claim.id) for claim in claims]
    if claim_ids:
        for evidence in session.execute(
            select(ClaimEvidence).where(ClaimEvidence.claim_id.in_(claim_ids))
        ).scalars():
            evidence_by_claim[int(evidence.claim_id)].append(evidence)
    return events_by_fingerprint, links_by_event, claims_by_event, evidence_by_claim


def upsert_manual_claim(
    session: Session,
    event_id: int,
    *,
    claim_key: str,
    claim_type: str,
    text: str,
    status: str,
    evidence: list[dict[str, Any]],
    confidence: float | None = None,
    normalized_value: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write a reviewed fact plus support/contradiction evidence and version it."""
    if claim_type in {"event_summary", "identity"}:
        raise ValueError("automatic claim types cannot be written through the manual claim API")
    if status not in {"unverified", "confirmed", "disputed", "rejected"}:
        raise ValueError("invalid claim status")
    if not claim_key.strip() or not text.strip():
        raise ValueError("claim_key and text are required")
    if not evidence:
        raise ValueError("a manual claim requires at least one evidence row")
    normalized_evidence: dict[tuple[int, str], dict[str, Any]] = {}
    for row in evidence:
        document_id = int(row["document_id"])
        stance = str(row.get("stance", "support"))
        if stance not in {"support", "contradict", "context"}:
            raise ValueError(f"invalid claim evidence stance: {stance}")
        normalized_evidence[(document_id, stance)] = {
            "document_id": document_id,
            "stance": stance,
            "evidence_level": row.get("evidence_level"),
            "excerpt": row.get("excerpt"),
        }
    document_ids = {document_id for document_id, _stance in normalized_evidence}
    existing_document_ids = set(
        int(value)
        for value in session.execute(
            select(Document.id).where(Document.id.in_(document_ids))
        ).scalars()
    )
    if existing_document_ids != document_ids:
        raise ValueError("claim evidence references an unknown document")

    event = session.execute(
        select(Event).where(Event.id == event_id).with_for_update()
    ).scalar_one_or_none()
    if event is None:
        raise KeyError(f"event not found: {event_id}")
    links = {
        int(link.document_id): (link.evidence_level, link.relation_reason)
        for link in session.execute(
            select(EventDocument).where(EventDocument.event_id == event.id)
        ).scalars()
    }
    before = _snapshot_payload(event, links, _claim_snapshot(session, int(event.id)))
    bounded_key = _claim_key(claim_key.strip())
    claim = session.execute(
        select(Claim)
        .where(Claim.event_id == event.id, Claim.claim_key == bounded_key)
        .with_for_update()
    ).scalar_one_or_none()
    if claim is None:
        claim = Claim(event_id=event.id, claim_key=bounded_key, claim_type=claim_type)
        session.add(claim)
    elif claim.claim_type in {"event_summary", "identity"}:
        raise ValueError("automatic claims cannot be overwritten")
    claim.claim_type = claim_type[:32]
    claim.text = text.strip()
    claim.normalized_value = normalized_value or {}
    claim.status = status
    claim.confidence = confidence
    claim.updated_at = datetime.now(UTC)
    session.flush()
    session.execute(delete(ClaimEvidence).where(ClaimEvidence.claim_id == claim.id))
    session.add_all(ClaimEvidence(claim_id=claim.id, **row) for row in normalized_evidence.values())
    session.flush()
    event.current_version += 1
    event.updated_at = datetime.now(UTC)
    after = _snapshot_payload(event, links, _claim_snapshot(session, int(event.id)))
    session.add(
        EventVersion(
            event_id=event.id,
            version=event.current_version,
            change_type="claim_changed",
            algorithm_version=CLUSTER_VERSION,
            snapshot=after,
            diff=_snapshot_diff(before, after),
        )
    )
    return {
        "event_id": int(event.id),
        "claim_id": int(claim.id),
        "claim_key": claim.claim_key,
        "event_version": event.current_version,
        "status": claim.status,
    }


def _apply_event_draft_local(
    session: Session,
    fingerprint: str,
    draft: EventDraft | None,
    *,
    events_by_fingerprint: dict[str, Event],
    links_by_event: dict[int, dict[int, EventDocument]],
    claims_by_event: dict[int, dict[str, Claim]],
    evidence_by_claim: dict[int, list[ClaimEvidence]],
) -> tuple[bool, bool, int]:
    event = events_by_fingerprint.get(fingerprint)
    old_links: dict[int, tuple[str | None, str | None]] = {}
    before: dict | None = None
    if event is not None:
        old_links = {
            document_id: (link.evidence_level, link.relation_reason)
            for document_id, link in links_by_event.get(int(event.id), {}).items()
        }
        before = _snapshot_payload(
            event,
            old_links,
            _claim_snapshot_from_rows(
                list(claims_by_event.get(int(event.id), {}).values()),
                evidence_by_claim,
            ),
        )
    created = event is None
    if draft is None:
        if event is None or event.status == "superseded":
            return False, False, 0
        event.status = "superseded"
        event.cluster_version = CLUSTER_VERSION
        event.current_version += 1
        event.updated_at = datetime.now(UTC)
        after = _snapshot_payload(
            event,
            old_links,
            _claim_snapshot_from_rows(
                list(claims_by_event.get(int(event.id), {}).values()),
                evidence_by_claim,
            ),
        )
        session.add(
            EventVersion(
                event_id=event.id,
                version=event.current_version,
                change_type="superseded",
                algorithm_version=CLUSTER_VERSION,
                snapshot=after,
                diff=_snapshot_diff(before, after),
            )
        )
        return False, True, 1

    desired_links: dict[int, tuple[str | None, str | None]] = {
        membership.document_id: (membership.evidence_level, membership.relation_reason)
        for membership in draft.memberships
    }
    desired_state = (
        draft.event_type,
        draft.topic,
        draft.category,
        draft.title,
        draft.summary,
        draft.status,
        draft.score,
        draft.evidence_level,
        CLUSTER_VERSION,
        draft.first_seen_at,
        draft.last_seen_at,
    )
    if event is None:
        event = Event(
            fingerprint=draft.fingerprint,
            event_type=draft.event_type,
            topic=draft.topic,
            category=draft.category,
            title=draft.title,
            summary=draft.summary,
            status=draft.status,
            score=draft.score,
            evidence_level=draft.evidence_level,
            cluster_version=CLUSTER_VERSION,
            first_seen_at=draft.first_seen_at,
            last_seen_at=draft.last_seen_at,
            current_version=1,
            updated_at=datetime.now(UTC),
        )
        session.add(event)
        session.flush()
        events_by_fingerprint[fingerprint] = event
        links_by_event[int(event.id)] = {}
        claims_by_event[int(event.id)] = {}
    else:
        current_state = (
            event.event_type,
            event.topic,
            event.category,
            event.title,
            event.summary,
            event.status,
            event.score,
            event.evidence_level,
            event.cluster_version,
            event.first_seen_at,
            event.last_seen_at,
        )
        if current_state == desired_state and old_links == desired_links:
            return False, False, 0
        (
            event.event_type,
            event.topic,
            event.category,
            event.title,
            event.summary,
            event.status,
            event.score,
            event.evidence_level,
            event.cluster_version,
            event.first_seen_at,
            event.last_seen_at,
        ) = desired_state
        event.current_version += 1
        event.updated_at = datetime.now(UTC)

    old_link_rows = links_by_event.setdefault(int(event.id), {})
    stale_document_ids = set(old_link_rows) - set(desired_links)
    if stale_document_ids:
        session.execute(
            delete(EventDocument).where(
                EventDocument.event_id == event.id,
                EventDocument.document_id.in_(stale_document_ids),
            )
        )
        for document_id in stale_document_ids:
            old_link_rows.pop(document_id, None)
    for document_id, (level, reason) in desired_links.items():
        link = old_link_rows.get(document_id)
        if link is None:
            link = EventDocument(
                event_id=event.id,
                document_id=document_id,
                stance="support",
                evidence_level=level,
                relation_reason=reason,
            )
            session.add(link)
            old_link_rows[document_id] = link
        else:
            link.stance = "support"
            link.evidence_level = level
            link.relation_reason = reason
    session.flush()
    claim_snapshot = _sync_claims(
        session,
        event,
        desired_links,
        existing=claims_by_event.setdefault(int(event.id), {}),
        evidence_by_claim=evidence_by_claim,
    )
    after = _snapshot_payload(
        event,
        desired_links,
        claim_snapshot,
    )
    change_type = (
        "created"
        if created
        else "evidence_changed"
        if before and before.get("evidence") != after.get("evidence")
        else "updated"
    )
    session.add(
        EventVersion(
            event_id=event.id,
            version=event.current_version,
            change_type=change_type,
            algorithm_version=CLUSTER_VERSION,
            snapshot=after,
            diff=_snapshot_diff(before, after),
        )
    )
    return created, not created, 1


def run_local_cluster(
    session: Session,
    *,
    limit: int = 1000,
    max_documents: int = 20000,
    trigger: str = "scheduler",
    scope: str = "all",
) -> dict[str, Any]:
    run = M2Run(
        stage="cluster",
        mode="replay" if trigger == "replay" else "incremental",
        algorithm_version=CLUSTER_VERSION,
        trigger=trigger,
        status="running",
    )
    session.add(run)
    session.flush()
    seed_ids, component_ids, work_ids = _claim_cluster_seeds(
        session, limit=limit, run_id=int(run.id), scope=scope
    )
    old_fingerprints = set(
        str(value)
        for value in session.execute(
            select(Event.fingerprint)
            .join(EventDocument, EventDocument.event_id == Event.id)
            .where(EventDocument.document_id.in_(seed_ids), ~Event.fingerprint.like("semantic:%"))
            .distinct()
        ).scalars()
    )
    if not seed_ids and not component_ids and not old_fingerprints:
        run.status = "success"
        run.finished_at = datetime.now(UTC)
        run.stats = {"status": "current", "scope": scope}
        return {"status": "current", "version": CLUSTER_VERSION, "due": 0, "run_id": run.id}

    document_ids, _identity_fingerprints = _expand_event_closure(
        session, component_ids, max_documents=max_documents, scope=scope
    )
    documents = load_documents(session, document_ids)
    decisions = _load_decisions(session, document_ids)
    drafts = build_event_drafts(documents, decisions)
    impacted_fingerprints = old_fingerprints | set(drafts)
    (
        events_by_fingerprint,
        links_by_event,
        claims_by_event,
        evidence_by_claim,
    ) = _load_event_batch_state(session, impacted_fingerprints)
    created = 0
    updated_count = 0
    versions = 0
    for fingerprint in sorted(impacted_fingerprints):
        was_created, was_updated, version_count = _apply_event_draft_local(
            session,
            fingerprint,
            drafts.get(fingerprint),
            events_by_fingerprint=events_by_fingerprint,
            links_by_event=links_by_event,
            claims_by_event=claims_by_event,
            evidence_by_claim=evidence_by_claim,
        )
        created += int(was_created)
        updated_count += int(was_updated)
        versions += version_count
    if document_ids:
        session.execute(
            update(Document)
            .where(Document.id.in_(document_ids))
            .values(cluster_version=CLUSTER_VERSION, clustered_at=datetime.now(UTC))
        )
    if work_ids:
        session.execute(
            update(M2WorkItem)
            .where(M2WorkItem.id.in_(work_ids))
            .values(status="done", completed_at=datetime.now(UTC))
        )
    stats = {
        "seeds": len(seed_ids),
        "affected_components": len(component_ids),
        "affected_documents": len(document_ids),
        "affected_events": len(impacted_fingerprints),
        "events_created": created,
        "events_updated": updated_count,
        "versions_created": versions,
    }
    run.status = "success"
    run.input_count = len(seed_ids)
    run.affected_count = len(document_ids)
    run.stats = stats
    run.finished_at = datetime.now(UTC)
    return {
        "status": "ok",
        "version": CLUSTER_VERSION,
        "due": len(seed_ids),
        "run_id": run.id,
        **stats,
    }


def queue_full_replay(
    session: Session, *, reason: str = "operator_replay", scope: str = "all"
) -> dict[str, int]:
    """Invalidate current derived versions once and record the replay request."""
    conditions = list(_scope_conditions(Document, scope))
    count = int(
        session.execute(
            select(func.count()).select_from(Document).where(*conditions)
        ).scalar_one()
    )
    session.execute(
        update(Document).where(*conditions).values(dedupe_version=None, cluster_version=None)
    )
    run = M2Run(
        stage="replay",
        mode="replay",
        algorithm_version=f"{DEDUPE_VERSION}/{CLUSTER_VERSION}",
        trigger="cli",
        status="success",
        input_count=count,
        affected_count=count,
        stats={"reason": reason, "queued_documents": count, "scope": scope},
        finished_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()
    return {"run_id": int(run.id), "queued_documents": count}


def record_failed_run(
    session: Session,
    *,
    stage: str,
    algorithm_version: str,
    trigger: str,
    error: str,
) -> None:
    session.add(
        M2Run(
            stage=stage,
            mode="replay" if trigger == "replay" else "incremental",
            algorithm_version=algorithm_version,
            trigger=trigger,
            status="failed",
            error=error[:4000],
            stats={},
            finished_at=datetime.now(UTC),
        )
    )


def supersede_stale_vuln_events(session: Session, *, limit: int = 2000) -> dict:
    """Supersede legacy 'cve:' events left by the pre-isolation clusterer.

    After the NVD isolation migration, structured-vuln CVEs get 'cve-nvd:' keys.
    Old 'cve:' events (same CVE, pre-namespace) remain and create one document
    mapping to two events. We mark the legacy events superseded (via EventVersion,
    preserving history) so only the current 'cve-nvd:' event remains active.
    """
    stale_fingerprints = set(
        session.execute(
            select(Event.fingerprint)
            .where(
                Event.category == "vuln_db",
                Event.status != "superseded",
                Event.fingerprint.like("cve:%"),
                ~Event.fingerprint.like("cve-nvd:%"),
            )
            .order_by(Event.id)
            .limit(limit)
        ).scalars()
    )
    if not stale_fingerprints:
        return {"superseded": 0, "remaining_stale": 0}

    events_by_fingerprint, links_by_event, claims_by_event, evidence_by_claim = (
        _load_event_batch_state(session, stale_fingerprints)
    )
    superseded = 0
    for fingerprint in sorted(stale_fingerprints):
        _created, updated, _versions = _apply_event_draft_local(
            session,
            fingerprint,
            None,  # draft None → supersede
            events_by_fingerprint=events_by_fingerprint,
            links_by_event=links_by_event,
            claims_by_event=claims_by_event,
            evidence_by_claim=evidence_by_claim,
        )
        if updated:
            superseded += 1
    session.flush()

    remaining = session.execute(
        select(func.count())
        .select_from(Event)
        .where(
            Event.category == "vuln_db",
            Event.status != "superseded",
            Event.fingerprint.like("cve:%"),
            ~Event.fingerprint.like("cve-nvd:%"),
        )
    ).scalar_one()
    return {"superseded": superseded, "remaining_stale": int(remaining)}
