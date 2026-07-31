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
) -> None:
    """Run a cost-bounded shadow semantic-enrichment batch."""
    from ai_security_hot.pipelines.semantic_stage import run_semantic_enrichment_stage

    _setup_logging()
    typer.echo(
        json.dumps(
            run_semantic_enrichment_stage(limit=limit, force=force),
            ensure_ascii=False,
        )
    )


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
) -> None:
    """Build non-destructive exact/near-duplicate relationships (M2)."""
    from ai_security_hot.pipelines.stages import run_dedupe_stage

    _setup_logging()
    typer.echo(json.dumps(run_dedupe_stage(force=force, trigger="cli")))


@app.command()
def cluster(
    force: bool = typer.Option(False, help="recompute even when version is current"),
) -> None:
    """Materialize strong-key events and their evidence links (M2)."""
    from ai_security_hot.pipelines.stages import run_cluster_stage

    _setup_logging()
    typer.echo(json.dumps(run_cluster_stage(force=force, trigger="cli")))


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
        if dedupe_result.get("status") == "current" or (
            dedupe_result.get("status") == "ok" and dedupe_result.get("remaining") == 0
        ):
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
        if cluster_result.get("status") == "current" or (
            cluster_result.get("status") == "ok" and cluster_result.get("remaining") == 0
        ):
            break
    complete = bool(cluster_result) and (
        cluster_result.get("status") == "current"
        or (cluster_result.get("status") == "ok" and cluster_result.get("remaining", 0) == 0)
    )
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


def main() -> None:
    get_settings()  # validate env early
    app()


if __name__ == "__main__":
    main()
