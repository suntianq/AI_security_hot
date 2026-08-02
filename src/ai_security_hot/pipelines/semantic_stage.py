"""Cost-bounded shadow semantic enrichment, isolated from deterministic M2."""

from __future__ import annotations

import logging
from time import monotonic

from ai_security_hot.config.models import resolve_model_config
from ai_security_hot.config.settings import get_settings
from ai_security_hot.llm.provider import provider_cache_namespace
from ai_security_hot.llm.registry import build_provider
from ai_security_hot.llm.tasks import ValidatedModelTaskRunner
from ai_security_hot.models.base import session_scope
from ai_security_hot.semantic.document_task import DocumentSemanticTask
from ai_security_hot.storage import repositories as repo
from ai_security_hot.storage import semantic_repository

log = logging.getLogger("intel.semantic")


def run_semantic_enrichment_stage(
    limit: int | None = None,
    *,
    force: bool = False,
    enqueue: bool = True,
    batch_id: str | None = None,
    document_ids: list[int] | None = None,
) -> dict:
    """Extract versioned entities/events/claims without changing current Events.

    ``document_ids`` restricts enqueueing to a specific doc set (used by the
    stratified eval sampler) — otherwise the stage enqueues recent eligible docs.
    """

    settings = get_settings()
    if batch_id is None:
        batch_id = settings.semantic_enrichment_batch_id
    enabled = getattr(settings, "semantic_enrichment_enabled", False)
    if not enabled and not force:
        return {"status": "disabled", "claimed": 0, "enriched": 0}

    batch_size = limit or getattr(settings, "semantic_enrichment_batch_size", 5)
    lease_seconds = getattr(settings, "semantic_enrichment_lease_seconds", 600)
    mode = getattr(settings, "semantic_enrichment_mode", "shadow")
    if mode != "shadow":
        raise ValueError("only shadow semantic enrichment is implemented")

    try:
        model_config = resolve_model_config(settings)
        provider = build_provider(settings, config=model_config)
    except ValueError as exc:
        log.warning("semantic enrichment configuration invalid: %s", exc)
        return {
            "status": "configuration_error",
            "claimed": 0,
            "enriched": 0,
            "error": str(exc),
        }

    task = DocumentSemanticTask(
        max_input_chars=model_config.max_input_chars,
        max_output_tokens=model_config.semantic_max_output_tokens,
    )
    runner = ValidatedModelTaskRunner(provider)
    provider_namespace = provider_cache_namespace(provider)
    execution_version = runner.prepare(task.spec, {}).execution_version

    with session_scope() as session:
        queued = (
            semantic_repository.enqueue_document_work(
                session,
                task=task.spec.name,
                task_version=task.spec.task_version,
                execution_version=execution_version,
                mode=mode,
                limit=batch_size,
                batch_id=batch_id,
                document_ids=document_ids,
            )
            if enqueue
            else 0
        )
        work = semantic_repository.claim_document_work(
            session,
            task=task.spec.name,
            execution_version=execution_version,
            limit=batch_size,
            lease_seconds=lease_seconds,
            batch_id=batch_id,
        )

    stats = {
        "status": "ok",
        "queued": queued,
        "claimed": len(work),
        "enriched": 0,
        "relevant": 0,
        "atomic_events": 0,
        "model_calls": 0,
        "cache_hits": 0,
        "failed": 0,
        "lease_lost": 0,
        "mode": mode,
        "task_version": task.spec.task_version,
        "prompt_version": task.spec.prompt_version,
        "execution_version": execution_version,
    }

    for index, item in enumerate(work):
        remaining_ids = [candidate.work_item_id for candidate in work[index:]]
        with session_scope() as session:
            owned = semantic_repository.extend_work_leases(
                session,
                remaining_ids,
                item.lease_token,
                lease_seconds=lease_seconds,
            )
        if item.work_item_id not in owned:
            stats["lease_lost"] += 1
            continue

        prepared = runner.prepare(task.spec, task.payload(item.document))
        cache_key = {
            "task": task.spec.name,
            "provider": provider_namespace,
            "model": provider.model,
            "prompt_version": task.spec.prompt_version,
            "input_hash": prepared.input_hash,
        }
        result = None
        with session_scope() as session:
            cached = repo.get_model_cache(session, **cache_key)
        if cached is not None:
            try:
                result = runner.validate_cached(prepared, cached)
            except Exception as exc:
                log.warning("discarding invalid semantic cache entry: %s", exc)
                with session_scope() as session:
                    repo.delete_model_cache(session, **cache_key)
                cached = None
            else:
                stats["cache_hits"] += 1

        started = monotonic()
        try:
            if result is None:
                stats["model_calls"] += 1
                result = runner.run(prepared)
                with session_scope() as session:
                    repo.put_model_cache(
                        session,
                        output=result.output.model_dump(mode="json"),
                        **cache_key,
                    )
            latency_ms = 0 if cached is not None else round((monotonic() - started) * 1000)
            with session_scope() as session:
                repo.record_model_run(
                    session,
                    document_id=item.document_id,
                    task=task.spec.name,
                    provider=provider_namespace,
                    model=provider.model,
                    prompt_version=task.spec.prompt_version,
                    input_hash=prepared.input_hash,
                    status="cache_hit" if cached is not None else "success",
                    latency_ms=latency_ms,
                    usage=result.usage,
                )
                semantic_repository.complete_document_work(
                    session,
                    work_item_id=item.work_item_id,
                    lease_token=item.lease_token,
                    document=item.document,
                    output=result.output,
                    input_hash=prepared.input_hash,
                    execution_version=execution_version,
                    enrichment_version=task.spec.task_version,
                    provider=provider_namespace,
                    model=provider.model,
                    prompt_version=task.spec.prompt_version,
                    finish_reason=result.finish_reason,
                    usage=result.usage,
                    raw_response=result.raw_response,
                    batch_id=batch_id,
                )
            stats["enriched"] += 1
            stats["relevant"] += int(result.output.relevant)
            stats["atomic_events"] += len(result.output.atomic_events)
        except semantic_repository.SemanticLeaseLost:
            log.warning("semantic lease lost after model work: %s", item.work_item_id)
            stats["lease_lost"] += 1
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            retry_seconds = min(86400, 60 * (2 ** min(item.attempts, 10)))
            # audit the failed call: usage + finish_reason if the runner had them
            failed_usage = result.usage if result is not None else None
            failed_finish = result.finish_reason if result is not None else None
            try:
                with session_scope() as session:
                    repo.record_model_run(
                        session,
                        document_id=item.document_id,
                        task=task.spec.name,
                        provider=provider_namespace,
                        model=provider.model,
                        prompt_version=task.spec.prompt_version,
                        input_hash=prepared.input_hash,
                        status="failed",
                        latency_ms=round((monotonic() - started) * 1000),
                        usage=failed_usage,
                        error=error,
                    )
                    semantic_repository.fail_document_work(
                        session,
                        work_item_id=item.work_item_id,
                        lease_token=item.lease_token,
                        error=error,
                        retry_after_seconds=retry_seconds,
                        finish_reason=failed_finish,
                        usage=failed_usage,
                    )
            except semantic_repository.SemanticLeaseLost:
                stats["lease_lost"] += 1
                continue
            log.warning("semantic enrichment failed for document %s: %s", item.document_id, error)
            stats["failed"] += 1
    return stats
