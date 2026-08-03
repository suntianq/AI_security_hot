"""Typer CLI — the single operational entry point.

intel sync              # load sources.yaml into the DB
intel fetch [--limit N] # run one fetch stage pass
intel normalize         # run one normalize stage pass
intel retry-failed      # requeue deterministic parse failures after a fix
intel run-once          # fetch + normalize once (used by e2e test)
intel dedupe            # build versioned duplicate relationships
intel cluster           # materialize events and evidence links
intel worker            # start the blocking scheduler
intel serve             # start the API (uvicorn)
intel self-check        # print the self-check report
intel stats             # print pipeline stats
intel export            # export documents to json/jsonl/csv
"""

from __future__ import annotations

import json
import logging

import typer

from ai_security_hot.config.settings import get_settings
from ai_security_hot.config.sources import load_registry
from ai_security_hot.models.base import session_scope
from ai_security_hot.storage import repositories as repo

app = typer.Typer(add_completion=False, help="AI Security Hot intel backend CLI")


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@app.command()
def sync() -> None:
    """Load sources.yaml into the DB (idempotent upsert)."""
    _setup_logging()
    registry = load_registry()
    with session_scope() as session:
        repo.sync_registry(session, registry)
    typer.echo(f"synced {len(registry.sources)} sources, {len(registry.endpoints)} endpoints")


@app.command()
def fetch(limit: int = 5) -> None:
    from ai_security_hot.pipelines.stages import run_fetch_stage

    _setup_logging()
    typer.echo(json.dumps(run_fetch_stage(limit=limit)))


@app.command()
def normalize(limit: int = 50) -> None:
    from ai_security_hot.pipelines.stages import run_normalize_stage

    _setup_logging()
    typer.echo(json.dumps(run_normalize_stage(limit=limit)))


@app.command("run-once")
def run_once(limit: int = 5) -> None:
    """Fetch + normalize + fulltext a single pass — used by the e2e test."""
    from ai_security_hot.pipelines.stages import (
        run_classify_stage,
        run_cluster_stage,
        run_dedupe_stage,
        run_fetch_stage,
        run_fulltext_stage,
        run_normalize_stage,
    )

    _setup_logging()
    fetch_stats = run_fetch_stage(limit=limit)
    norm_stats = run_normalize_stage()
    ft_stats = run_fulltext_stage()
    classify_stats = run_classify_stage()
    dedupe_stats = run_dedupe_stage()
    cluster_stats = run_cluster_stage()
    typer.echo(
        json.dumps(
            {
                "fetch": fetch_stats,
                "normalize": norm_stats,
                "fulltext": ft_stats,
                "classify": classify_stats,
                "dedupe": dedupe_stats,
                "cluster": cluster_stats,
            }
        )
    )


@app.command("retry-failed")
def retry_failed(
    limit: int = typer.Option(500, min=1),
    endpoint_id: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """Requeue failed normalization rows after fixing their parser/config."""
    _setup_logging()
    with session_scope() as session:
        retried = repo.retry_failed_stage_items(session, limit=limit, endpoint_id=endpoint_id)
    typer.echo(json.dumps({"retried": retried, "endpoint": endpoint_id}))


@app.command()
def fulltext(limit: int = 20) -> None:
    """Second-fetch full text for fulltext-enabled endpoints."""
    from ai_security_hot.pipelines.stages import run_fulltext_stage

    _setup_logging()
    typer.echo(json.dumps(run_fulltext_stage(limit=limit)))


@app.command()
def classify(limit: int = 500) -> None:
    """Classify documents in configured rule or cached hybrid mode (M1.3)."""
    from ai_security_hot.pipelines.stages import run_classify_stage

    _setup_logging()
    typer.echo(json.dumps(run_classify_stage(limit=limit)))


@app.command("semantic-enrich")
def semantic_enrich(
    limit: int = typer.Option(5, min=1, max=100),
    force: bool = typer.Option(
        False,
        "--force",
        help="run one shadow batch even when scheduled enrichment is disabled",
    ),
    retry_only: bool = typer.Option(
        False,
        "--retry-only",
        help="claim due retries without enqueueing new documents",
    ),
    batch: str | None = typer.Option(
        None,
        "--batch",
        help="tag this run with a reproducible batch id (e.g. m2.2.2-eval-v1)",
    ),
    manifest: str | None = typer.Option(
        None,
        "--manifest",
        help="JSONL sample manifest — enqueue exactly those document ids (controlled eval)",
    ),
) -> None:
    """Run a cost-bounded shadow semantic-enrichment batch."""
    from ai_security_hot.pipelines.semantic_stage import run_semantic_enrichment_stage
    from ai_security_hot.semantic.sampling import load_manifest

    _setup_logging()
    document_ids = load_manifest(manifest) if manifest else None
    typer.echo(
        json.dumps(
            run_semantic_enrichment_stage(
                limit=limit,
                force=force,
                enqueue=not retry_only,
                batch_id=batch,
                document_ids=document_ids,
            ),
            ensure_ascii=False,
        )
    )


@app.command("semantic-eval")
def semantic_eval(
    batch: str = typer.Option(..., "--batch", help="batch id to evaluate"),
    manifest: str | None = typer.Option(
        None, "--manifest", help="sample manifest JSONL (for coverage report)"
    ),
) -> None:
    """Aggregate proxy metrics for a semantic-evaluation batch (M2.2.2)."""
    from ai_security_hot.semantic.evaluation import evaluate_batch

    _setup_logging()
    typer.echo(json.dumps(evaluate_batch(batch, manifest=manifest), ensure_ascii=False, indent=2))


@app.command("claim-merge")
def claim_merge(limit: int = typer.Option(200, min=1)) -> None:
    """Merge claims for same-event atomic-event pairs (M2.4, shadow summary)."""
    from ai_security_hot.models.base import session_scope
    from ai_security_hot.semantic.claim_merge_repo import run_claim_merge

    _setup_logging()
    with session_scope() as session:
        typer.echo(json.dumps(run_claim_merge(session, limit=limit), ensure_ascii=False))


@app.command("event-promote")
def event_promote(
    limit: int = typer.Option(1000, min=1),
    apply: bool = typer.Option(
        False, "--apply", help="persist gated same-event components; preview is default"
    ),
) -> None:
    """Preview or apply stable connected components built only from same_event edges."""
    from collections import Counter

    from sqlalchemy import select

    from ai_security_hot.models.base import session_scope
    from ai_security_hot.models.semantic_tables import AtomicEvent
    from ai_security_hot.models.tables import Document
    from ai_security_hot.semantic.claim_merge import merge_claims
    from ai_security_hot.semantic.claim_merge_repo import _load_claims_for_atomics
    from ai_security_hot.semantic.promotion import (
        apply_promotion,
        build_promotion_preview,
        load_same_event_components,
    )

    _setup_logging()
    with session_scope() as session:
        components = load_same_event_components(session, limit=limit)
        atomic_ids = {value for component in components for value in component.atomic_ids}
        claims_by_atomic = _load_claims_for_atomics(session, atomic_ids)
        atomic_rows = {
            int(row.id): row
            for row in session.execute(
                select(
                    AtomicEvent.id,
                    AtomicEvent.document_id,
                    AtomicEvent.event_type,
                    AtomicEvent.summary,
                    AtomicEvent.confidence,
                    Document.published_at_utc,
                    Document.tech_directions,
                )
                .join(Document, Document.id == AtomicEvent.document_id)
                .where(AtomicEvent.id.in_(atomic_ids))
            )
        }
        previews = []
        for component in components:
            source_claims = [
                claim
                for atomic_id in component.atomic_ids
                for claim in claims_by_atomic.get(atomic_id, [])
            ]
            if not source_claims:
                continue
            merged = merge_claims(source_claims)
            rows = [atomic_rows[value] for value in component.atomic_ids if value in atomic_rows]
            if not rows:
                continue
            document_ids = sorted({int(row.document_id) for row in rows})
            best_atomic = max(rows, key=lambda row: (float(row.confidence), -int(row.id)))
            title = str(best_atomic.summary)[:160]
            summary = " ".join(item.text for item in merged[:3])[:500]
            event_type = Counter(str(row.event_type) for row in rows).most_common(1)[0][0]
            topics = [
                str(topic)
                for row in rows
                for topic in (row.tech_directions or [])
                if topic != "cve"
            ]
            topic = Counter(topics).most_common(1)[0][0] if topics else "security_for_ai"
            published_times = [row.published_at_utc for row in rows if row.published_at_utc]
            first_seen_at = min(published_times) if published_times else None
            last_seen_at = max(published_times) if published_times else None
            preview = build_promotion_preview(
                fingerprint=component.fingerprint,
                title=title,
                summary=summary,
                event_type=event_type,
                topic=topic,
                category="general",
                document_ids=document_ids,
                merged_claim_count=len(merged),
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
            )
            payload = {
                **preview.as_dict(),
                "component_id": component.id,
                "component_revision": component.revision,
                "atomic_ids": component.atomic_ids,
            }
            if apply and preview.gated:
                promotion, changed = apply_promotion(
                    session,
                    preview,
                    merged,
                    atomic_ids=component.atomic_ids,
                    relation_component_id=component.id,
                    component_key=component.component_key,
                    component_revision=component.revision,
                )
                payload.update({"promotion_id": promotion.id, "applied": changed})
            previews.append(payload)
        gated = sum(1 for item in previews if item["gated"])
        typer.echo(
            json.dumps(
                {"components": len(previews), "gated_met": gated, "sample": previews[:5]},
                ensure_ascii=False,
                indent=2,
            )
        )


@app.command("relation-scan")
def relation_scan(
    limit: int = typer.Option(500, min=1),
) -> None:
    """Scan cross-document atomic-event candidate pairs and adjudicate (M2.3, shadow)."""
    from ai_security_hot.config.settings import get_settings
    from ai_security_hot.semantic.candidate_scan import run_incremental_relation_scan
    from ai_security_hot.semantic.components import run_component_stage

    _setup_logging()
    summary = run_incremental_relation_scan(seed_limit=limit, pair_limit=limit, work_limit=limit)
    summary["components"] = run_component_stage(
        discovery_limit=limit * 5,
        work_limit=limit,
        max_atomic_events=get_settings().m2_max_local_documents,
    )
    typer.echo(json.dumps(summary, ensure_ascii=False))


@app.command("semantic-sample")
def semantic_sample(
    size: int = typer.Option(100, min=1, max=500, help="sample size"),
    batch: str = typer.Option(
        "m2.2.2-eval-v1", "--batch", help="reproducible batch id for the sample"
    ),
    manifest: str | None = typer.Option(
        None, "--manifest", help="write the sample manifest to this JSONL path"
    ),
) -> None:
    """Draw a stratified sample of non-CVE docs and write a reproducible manifest."""
    from ai_security_hot.semantic.sampling import run_sampling

    _setup_logging()
    result = run_sampling(size=size, batch_id=batch, manifest=manifest)
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("llm-config")
def llm_config() -> None:
    """Validate and print the effective model config without exposing secrets."""
    from ai_security_hot.config.models import resolve_model_config
    from ai_security_hot.llm.registry import provider_names

    try:
        model_config = resolve_model_config(get_settings())
    except ValueError as exc:
        typer.echo(
            json.dumps(
                {"status": "configuration_error", "error": str(exc)},
                ensure_ascii=False,
                indent=2,
            )
        )
        raise typer.Exit(code=2) from exc
    summary = model_config.public_summary()
    summary["provider_registered"] = model_config.provider in provider_names()
    summary["status"] = (
        "ready" if summary["ready"] and summary["provider_registered"] else "not_ready"
    )
    typer.echo(json.dumps(summary, ensure_ascii=False, indent=2))


@app.command("evaluate-m2")
def evaluate_m2(
    dataset: str = typer.Option(
        "evaluation/m2_quality_seed.jsonl", help="JSONL quality-label dataset"
    ),
    top_n: int = typer.Option(10, min=1),
    review_status: str | None = typer.Option(
        None,
        "--review-status",
        help="evaluate only one label state; use reviewed for release gates",
    ),
) -> None:
    """Evaluate deterministic dedupe, clustering and ranking quality offline."""
    from ai_security_hot.events.evaluation import evaluate_dataset

    typer.echo(
        json.dumps(
            evaluate_dataset(dataset, top_n=top_n, review_status=review_status),
            ensure_ascii=False,
            indent=2,
        )
    )


@app.command("m2-index")
def m2_index(
    batch_size: int = typer.Option(5000, min=100, max=20000),
    complete: bool = typer.Option(False, "--all", help="continue until index is current"),
) -> None:
    """Backfill versioned URL/title/content/identity/LSH candidate indexes."""
    from ai_security_hot.storage import event_repository

    total = 0
    while True:
        with session_scope() as session:
            result = event_repository.backfill_signature_batch(session, limit=batch_size)
        total += result["indexed"]
        if not complete or result["remaining"] == 0 or result["indexed"] == 0:
            typer.echo(json.dumps({**result, "indexed_total": total}))
            return


@app.command("m2-reviews")
def m2_reviews(
    status: str = typer.Option("pending", help="pending | approved | rejected"),
    limit: int = typer.Option(50, min=1, max=500),
) -> None:
    """List low-confidence or hard-conflict M2 candidate reviews."""
    if status not in {"pending", "approved", "rejected"}:
        raise typer.BadParameter("status must be pending, approved or rejected")
    from ai_security_hot.storage import event_repository

    with session_scope() as session:
        rows = event_repository.list_candidate_reviews(session, status=status, limit=limit)
    typer.echo(json.dumps(rows, ensure_ascii=False, indent=2))


@app.command("m2-token-stats")
def m2_token_stats() -> None:
    """Rebuild persistent current-document counts for candidate token buckets."""
    from ai_security_hot.storage import event_repository

    with session_scope() as session:
        buckets = event_repository.rebuild_block_token_stats(session)
    typer.echo(json.dumps({"status": "ok", "buckets": buckets}))


@app.command("resolve-m2-review")
def resolve_m2_review(
    review_id: int,
    decision: str = typer.Option(..., help="approved | rejected"),
    reviewer: str = typer.Option(..., help="auditable reviewer identity"),
    notes: str | None = typer.Option(None),
) -> None:
    """Resolve a candidate and queue only its affected dedupe/event graph."""
    if decision not in {"approved", "rejected"}:
        raise typer.BadParameter("decision must be approved or rejected")
    from ai_security_hot.storage import event_repository

    with session_scope() as session:
        result = event_repository.resolve_candidate_review(
            session,
            review_id,
            decision=decision,
            reviewer=reviewer,
            notes=notes,
        )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command()
def dedupe(
    force: bool = typer.Option(False, help="queue a full replay, then process its first batch"),
    scope: str = typer.Option(
        "all",
        "--scope",
        help="all | vuln (NVD/KEV) | general — run one pass restricted to a scope",
    ),
) -> None:
    """Build non-destructive exact/near-duplicate relationships (M2)."""
    from ai_security_hot.pipelines.stages import run_dedupe_stage

    _setup_logging()
    typer.echo(json.dumps(run_dedupe_stage(force=force, trigger="cli", scope=scope)))


@app.command()
def cluster(
    force: bool = typer.Option(False, help="recompute even when version is current"),
    scope: str = typer.Option(
        "all",
        "--scope",
        help="all | vuln (NVD/KEV) | general — run one pass restricted to a scope",
    ),
) -> None:
    """Materialize strong-key events and their evidence links (M2)."""
    from ai_security_hot.pipelines.stages import run_cluster_stage

    _setup_logging()
    typer.echo(json.dumps(run_cluster_stage(force=force, trigger="cli", scope=scope)))


def _m2_stage_done(result: dict) -> bool:
    """True when a pass (or the merged vuln+general pass) has no backlog left.

    With scope="all" the merged ``status`` reflects the first sub-scope to run;
    ``remaining`` carries the true combined backlog, so a "current" status alone
    must not end the replay loop early.
    """
    return result.get("status") in {"current", "ok"} and result.get("remaining", 0) == 0


def _run_m2_replay(max_batches: int, *, resume: bool = False) -> dict:
    from ai_security_hot.pipelines.stages import run_cluster_stage, run_dedupe_stage
    from ai_security_hot.storage import event_repository

    if resume:
        queued = {"run_id": None, "queued_documents": 0, "resumed": True}
    else:
        with session_scope() as session:
            queued = event_repository.queue_full_replay(session)
    dedupe_result: dict = {}
    cluster_result: dict = {}
    batches = 0
    while batches < max_batches:
        dedupe_result = run_dedupe_stage(trigger="replay")
        batches += 1
        if _m2_stage_done(dedupe_result):
            break
    if dedupe_result.get("remaining", 0) or dedupe_result.get("status") == "indexing":
        return {
            "status": "partial",
            "queued": queued,
            "batches": batches,
            "dedupe": dedupe_result,
            "cluster": cluster_result,
        }
    while batches < max_batches:
        cluster_result = run_cluster_stage(trigger="replay")
        batches += 1
        if _m2_stage_done(cluster_result):
            break
    complete = bool(cluster_result) and _m2_stage_done(cluster_result)
    return {
        "status": "complete" if complete else "partial",
        "queued": queued,
        "batches": batches,
        "dedupe": dedupe_result,
        "cluster": cluster_result,
    }


@app.command("replay-m2")
def replay_m2(
    max_batches: int = typer.Option(10000, min=1),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="continue existing version/work backlog without invalidating completed batches",
    ),
) -> None:
    """Replay M2.1 in bounded local batches with durable run audit."""
    _setup_logging()
    typer.echo(json.dumps(_run_m2_replay(max_batches, resume=resume)))


@app.command("supersede-stale-vuln")
def supersede_stale_vuln(limit: int = typer.Option(2000, min=1)) -> None:
    """Supersede legacy pre-isolation 'cve:' events (keep 'cve-nvd:' active)."""
    from ai_security_hot.models.base import session_scope
    from ai_security_hot.storage import event_repository

    _setup_logging()
    with session_scope() as session:
        typer.echo(json.dumps(event_repository.supersede_stale_vuln_events(session, limit=limit)))


@app.command("eventize")
def eventize(force: bool = typer.Option(False, help="recompute both M2 stages")) -> None:
    """Run dedupe then event clustering as one operational command."""
    from ai_security_hot.pipelines.stages import run_cluster_stage, run_dedupe_stage

    _setup_logging()
    if force:
        typer.echo(json.dumps(_run_m2_replay(10000)))
        return
    typer.echo(
        json.dumps(
            {
                "dedupe": run_dedupe_stage(trigger="cli"),
                "cluster": run_cluster_stage(trigger="cli"),
            }
        )
    )


@app.command()
def worker() -> None:
    from ai_security_hot.jobs.scheduler import run_worker

    _setup_logging()
    run_worker()


@app.command()
def serve(host: str = "0.0.0.0", port: int = 8000) -> None:  # noqa: S104
    import uvicorn

    _setup_logging()
    uvicorn.run("ai_security_hot.api.app:app", host=host, port=port, log_level="info")


@app.command("self-check")
def self_check() -> None:
    from ai_security_hot.jobs.self_check import run_self_check

    _setup_logging()
    typer.echo(json.dumps(run_self_check(), ensure_ascii=False))


@app.command()
def export(
    fmt: str = typer.Option("json", "--format", "-f", help="json | jsonl | csv"),
    out: str | None = typer.Option(None, "--out", "-o", help="output file (default: stdout)"),
    source: str | None = typer.Option(None, "--source", "-s", help="filter by endpoint id"),
    min_quality: float = typer.Option(0.0, "--min-quality", help="minimum parse_quality"),
    limit: int | None = typer.Option(None, "--limit", "-n", help="max rows"),
) -> None:
    """Export documents to json / jsonl / csv (file or stdout)."""
    import csv
    import sys

    from ai_security_hot.storage.repositories import iter_documents_for_export

    fmt = fmt.lower()
    if fmt not in ("json", "jsonl", "csv"):
        typer.echo(f"unknown format: {fmt!r} (use json|jsonl|csv)", err=True)
        raise typer.Exit(code=2)

    fh = open(out, "w", encoding="utf-8", newline="") if out else sys.stdout
    count = 0
    try:
        with session_scope() as session:
            rows = iter_documents_for_export(
                session, source=source, min_quality=min_quality, limit=limit
            )
            if fmt == "jsonl":
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                    count += 1
            elif fmt == "json":
                fh.write("[")
                for i, row in enumerate(rows):
                    fh.write(("," if i else "") + json.dumps(row, ensure_ascii=False))
                    count += 1
                fh.write("]")
            else:  # csv
                writer = None
                for row in rows:
                    flat = {k: (";".join(v) if isinstance(v, list) else v) for k, v in row.items()}
                    if writer is None:
                        writer = csv.DictWriter(fh, fieldnames=list(flat.keys()))
                        writer.writeheader()
                    writer.writerow(flat)
                    count += 1
    finally:
        if out:
            fh.close()
    if out:
        typer.echo(f"exported {count} documents -> {out} ({fmt})")


@app.command()
def stats() -> None:
    from sqlalchemy import func, select

    from ai_security_hot.models.tables import Document, Event, EventDocument, RawItem

    with session_scope() as session:
        rows = session.execute(select(RawItem.stage, func.count()).group_by(RawItem.stage)).all()
        by_stage = {stage: count for stage, count in rows}
        docs = session.execute(select(func.count()).select_from(Document)).scalar_one()
        duplicates = session.execute(
            select(func.count()).select_from(Document).where(Document.near_dup_of.is_not(None))
        ).scalar_one()
        events = session.execute(
            select(func.count()).select_from(Event).where(Event.status == "detected")
        ).scalar_one()
        evidence_links = session.execute(
            select(func.count()).select_from(EventDocument)
        ).scalar_one()
    typer.echo(
        json.dumps(
            {
                "raw_items_by_stage": by_stage,
                "documents": docs,
                "near_duplicates": duplicates,
                "events": events,
                "event_documents": evidence_links,
            }
        )
    )


@app.command("event-promotion-rollback")
def event_promotion_rollback(promotion_id: int = typer.Option(..., "--promotion-id")) -> None:
    """Rollback the exact event version written by one semantic promotion."""
    from ai_security_hot.models.base import session_scope
    from ai_security_hot.semantic.promotion import rollback_promotion

    with session_scope() as session:
        promotion, changed = rollback_promotion(session, promotion_id)
        typer.echo(json.dumps({"promotion_id": promotion.id, "rolled_back": changed}))


@app.command("daily-snapshot")
def daily_snapshot(
    date_value: str = typer.Option(..., "--date"),
    tz: str = typer.Option("Asia/Shanghai"),
    category: str | None = typer.Option(None),
    limit: int = typer.Option(100, min=1, max=500),
) -> None:
    """Freeze one reproducible daily-hotspot revision (idempotent by content)."""
    from datetime import date as date_type

    from ai_security_hot.models.base import session_scope
    from ai_security_hot.snapshots import generate_daily_snapshot

    natural_date = date_type.fromisoformat(date_value)
    with session_scope() as session:
        row = generate_daily_snapshot(
            session, natural_date=natural_date, timezone=tz, category=category, limit=limit
        )
        typer.echo(
            json.dumps(
                {
                    "snapshot_id": row.id,
                    "revision": row.revision,
                    "items": row.item_count,
                    "as_of": row.generated_at.isoformat(),
                }
            )
        )


def main() -> None:
    get_settings()  # validate env early
    app()


if __name__ == "__main__":
    main()
