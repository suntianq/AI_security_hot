"""Self-check job (MVP 16 / plan): surface silent failures.

Flags endpoints that are stale or degraded, deterministic parse failures,
and raw/classification work whose database lease expired.
In M0 it logs a structured report; wiring to an alert channel is a later step.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from ai_security_hot.config.embeddings import resolve_embedding_config
from ai_security_hot.config.models import resolve_model_config
from ai_security_hot.config.settings import get_settings
from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.embeddings.provider import embedding_provider_names
from ai_security_hot.events.intelligence import CLUSTER_VERSION, DEDUPE_VERSION
from ai_security_hot.llm.registry import provider_names
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.semantic_tables import (
    AtomicEventEmbedding,
    RelationCandidate,
    SemanticComponentWorkItem,
    SemanticRelationComponent,
    SemanticRelationMembership,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import (
    CandidateReview,
    Claim,
    Document,
    DocumentBlockTokenStat,
    Event,
    EventVersion,
    M2Run,
    M2WorkItem,
    ModelRun,
    RawItem,
    SourceEndpoint,
)
from ai_security_hot.storage import event_repository
from ai_security_hot.storage import repositories as repo

log = logging.getLogger("intel.self_check")


def run_self_check() -> dict:
    now = datetime.now(UTC)
    report: dict = {
        "stale": [],
        "degraded": [],
        "circuit_open": [],
        "stuck_items": 0,
        "failed_items": 0,
        "event_pipeline": {},
        "m2_incremental": {},
        "semantic_relation": {},
        "embedding": {},
        "classification": {},
        "data_quality": {},
    }

    with session_scope() as session:
        endpoints = (
            session.execute(select(SourceEndpoint).where(SourceEndpoint.enabled.is_(True)))
            .scalars()
            .all()
        )

        for ep in endpoints:
            if ep.status == "circuit_open":
                report["circuit_open"].append(
                    {"id": ep.id, "failures": ep.consecutive_failures, "error": ep.last_error}
                )
            elif ep.status == "degraded" or ep.consecutive_failures >= 3:
                report["degraded"].append(
                    {"id": ep.id, "failures": ep.consecutive_failures, "error": ep.last_error}
                )
            # stale = no success within 3x the endpoint interval
            interval = int((ep.policy or {}).get("schedule", {}).get("interval_minutes", 60))
            if ep.last_success_at is not None:
                overdue_min = (now - ep.last_success_at).total_seconds() / 60
                if overdue_min > 3 * interval:
                    report["stale"].append({"id": ep.id, "overdue_minutes": round(overdue_min)})

        stuck = session.execute(
            select(func.count())
            .select_from(RawItem)
            .where(
                RawItem.stage.notin_([PipelineStage.DONE.value, PipelineStage.FAILED.value]),
                RawItem.stage_lease_until.is_not(None),
                RawItem.stage_lease_until < now,
            )
        ).scalar_one()
        failed = session.execute(
            select(func.count())
            .select_from(RawItem)
            .where(RawItem.stage == PipelineStage.FAILED.value)
        ).scalar_one()
        report["stuck_items"] = int(stuck)
        report["failed_items"] = int(failed)
        dedupe_due = repo.count_dedupe_due(session, version=DEDUPE_VERSION)
        cluster_due = repo.count_cluster_due(session, version=CLUSTER_VERSION)
        events = session.execute(
            select(func.count()).select_from(Event).where(Event.status == "detected")
        ).scalar_one()
        report["event_pipeline"] = {
            "dedupe_due": int(dedupe_due),
            "cluster_due": int(cluster_due),
            "events": int(events),
        }
        work_rows = session.execute(
            select(M2WorkItem.stage, func.count())
            .where(M2WorkItem.status == "pending")
            .group_by(M2WorkItem.stage)
        ).all()
        pending_reviews = session.execute(
            select(func.count())
            .select_from(CandidateReview)
            .where(CandidateReview.status == "pending")
        ).scalar_one()
        event_versions = session.execute(
            select(func.count()).select_from(EventVersion)
        ).scalar_one()
        claims = session.execute(select(func.count()).select_from(Claim)).scalar_one()
        block_token_buckets = session.execute(
            select(func.count()).select_from(DocumentBlockTokenStat)
        ).scalar_one()
        failed_m2_runs = session.execute(
            select(func.count())
            .select_from(M2Run)
            .where(M2Run.status == "failed", M2Run.started_at >= now - timedelta(days=1))
        ).scalar_one()
        report["m2_incremental"] = {
            "signature_due": event_repository.count_signature_due(session),
            "work_pending": {str(stage): int(count) for stage, count in work_rows},
            "reviews_pending": int(pending_reviews),
            "event_versions": int(event_versions),
            "claims": int(claims),
            "block_token_buckets": int(block_token_buckets),
            "failed_runs_24h": int(failed_m2_runs),
        }
        component_work_rows = session.execute(
            select(SemanticComponentWorkItem.status, func.count()).group_by(
                SemanticComponentWorkItem.status
            )
        ).all()
        active_components = session.execute(
            select(func.count())
            .select_from(SemanticRelationComponent)
            .where(SemanticRelationComponent.status == "active")
        ).scalar_one()
        active_memberships = session.execute(
            select(func.count())
            .select_from(SemanticRelationMembership)
            .where(SemanticRelationMembership.active.is_(True))
        ).scalar_one()
        expired_component_leases = session.execute(
            select(func.count())
            .select_from(SemanticComponentWorkItem)
            .where(
                SemanticComponentWorkItem.status == "running",
                SemanticComponentWorkItem.lease_until < now,
            )
        ).scalar_one()
        report["semantic_relation"] = {
            "active_components": int(active_components),
            "active_memberships": int(active_memberships),
            "work_status": {str(status): int(count) for status, count in component_work_rows},
            "expired_leases": int(expired_component_leases),
        }
        embedding_work_rows = session.execute(
            select(SemanticWorkItem.status, func.count())
            .where(SemanticWorkItem.task == "atomic_embedding")
            .group_by(SemanticWorkItem.status)
        ).all()
        embedding_vectors = session.execute(
            select(func.count()).select_from(AtomicEventEmbedding)
        ).scalar_one()
        embedding_candidates = session.execute(
            select(RelationCandidate.status, func.count())
            .where(RelationCandidate.embedding_score.is_not(None))
            .group_by(RelationCandidate.status)
        ).all()
        expired_embedding_leases = session.execute(
            select(func.count())
            .select_from(SemanticWorkItem)
            .where(
                SemanticWorkItem.task == "atomic_embedding",
                SemanticWorkItem.status == "running",
                SemanticWorkItem.lease_until < now,
            )
        ).scalar_one()
        report["embedding"] = {
            "vectors": int(embedding_vectors),
            "work_status": {str(status): int(count) for status, count in embedding_work_rows},
            "candidate_status": {str(status): int(count) for status, count in embedding_candidates},
            "expired_leases": int(expired_embedding_leases),
        }
        record_status_rows = session.execute(
            select(Document.record_status, func.count()).group_by(Document.record_status)
        ).all()
        source_status_rows = session.execute(
            select(Document.source_status, func.count()).group_by(Document.source_status)
        ).all()
        current_documents = session.execute(
            select(func.count()).select_from(Document).where(*repo.current_document_conditions())
        ).scalar_one()
        report["data_quality"] = {
            "current_documents": int(current_documents),
            "record_status": {str(k): int(v) for k, v in record_status_rows},
            "source_status": {str(k): int(v) for k, v in source_status_rows},
        }
        expired_leases = session.execute(
            select(func.count())
            .select_from(Document)
            .where(
                Document.classify_lease_until.is_not(None),
                Document.classify_lease_until < now,
            )
        ).scalar_one()
        pending_retries = session.execute(
            select(func.count())
            .select_from(Document)
            .where(Document.classify_next_retry_at.is_not(None))
        ).scalar_one()
        recent_fallbacks = session.execute(
            select(func.count())
            .select_from(ModelRun)
            .where(ModelRun.status == "fallback", ModelRun.created_at >= now - timedelta(days=1))
        ).scalar_one()
        settings = get_settings()
        config_errors = []
        llm_required = (
            settings.classification_mode == "hybrid" or settings.semantic_enrichment_enabled
        )
        model_config = None
        try:
            model_config = resolve_model_config(settings)
        except ValueError as exc:
            if llm_required:
                config_errors.append(str(exc))
        if model_config is not None and llm_required:
            if model_config.provider not in provider_names():
                config_errors.append(f"unknown provider: {model_config.provider}")
            if not model_config.api_key_configured or not model_config.model:
                config_errors.append("model calls require INTEL_LLM_API_KEY and a configured model")
        embedding_errors = []
        embedding_config = None
        try:
            embedding_config = resolve_embedding_config(settings)
        except ValueError as exc:
            if settings.embedding_enabled:
                embedding_errors.append(str(exc))
        if embedding_config is not None and settings.embedding_enabled:
            if embedding_config.provider not in embedding_provider_names():
                embedding_errors.append(f"unknown embedding provider: {embedding_config.provider}")
            if not embedding_config.api_key_configured or not embedding_config.model:
                embedding_errors.append(
                    "embedding calls require INTEL_EMBEDDING_API_KEY and a configured model"
                )
        report["embedding"].update(
            {
                "enabled": settings.embedding_enabled,
                "profile": embedding_config.profile if embedding_config else None,
                "provider": (
                    embedding_config.provider if embedding_config else settings.embedding_provider
                ),
                "model": embedding_config.model if embedding_config else settings.embedding_model,
                "api_key_configured": (
                    embedding_config.api_key_configured
                    if embedding_config
                    else bool(settings.embedding_api_key)
                ),
                "config_errors": embedding_errors,
            }
        )
        report["classification"] = {
            "mode": settings.classification_mode,
            "semantic_enabled": settings.semantic_enrichment_enabled,
            "profile": model_config.profile if model_config else None,
            "provider": model_config.provider if model_config else settings.llm_provider,
            "model": model_config.model if model_config else settings.llm_model,
            "response_format": (
                model_config.response_format if model_config else settings.llm_response_format
            ),
            "thinking_mode": (
                model_config.thinking_mode if model_config else settings.llm_thinking_mode
            ),
            "api_key_configured": (
                model_config.api_key_configured if model_config else bool(settings.llm_api_key)
            ),
            "expired_leases": int(expired_leases),
            "pending_retries": int(pending_retries),
            "fallbacks_24h": int(recent_fallbacks),
            "config_errors": config_errors,
        }

    if (
        report["degraded"]
        or report["circuit_open"]
        or report["stale"]
        or report["stuck_items"]
        or report["failed_items"]
        or report["classification"]["config_errors"]
        or report["m2_incremental"]["failed_runs_24h"]
        or report["semantic_relation"]["work_status"].get("failed", 0)
        or report["semantic_relation"]["expired_leases"]
        or report["embedding"]["config_errors"]
        or report["embedding"]["work_status"].get("failed", 0)
        or report["embedding"]["expired_leases"]
    ):
        log.warning("self_check found issues: %s", report)
    else:
        log.info("self_check ok: all endpoints healthy")
    return report
