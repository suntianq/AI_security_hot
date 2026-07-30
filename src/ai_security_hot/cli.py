"""Typer CLI — the single operational entry point.

intel sync              # load sources.yaml into the DB
intel fetch [--limit N] # run one fetch stage pass
intel normalize         # run one normalize stage pass
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


@app.command()
def fulltext(limit: int = 20) -> None:
    """Second-fetch full text for fulltext-enabled endpoints."""
    from ai_security_hot.pipelines.stages import run_fulltext_stage

    _setup_logging()
    typer.echo(json.dumps(run_fulltext_stage(limit=limit)))


@app.command()
def classify(limit: int = 500) -> None:
    """Classify documents (M1.1 rule-based): tech_direction / company_model / event_type."""
    from ai_security_hot.pipelines.stages import run_classify_stage

    _setup_logging()
    typer.echo(json.dumps(run_classify_stage(limit=limit)))


@app.command()
def dedupe(
    force: bool = typer.Option(False, help="recompute even when version is current"),
) -> None:
    """Build non-destructive exact/near-duplicate relationships (M2)."""
    from ai_security_hot.pipelines.stages import run_dedupe_stage

    _setup_logging()
    typer.echo(json.dumps(run_dedupe_stage(force=force)))


@app.command()
def cluster(
    force: bool = typer.Option(False, help="recompute even when version is current"),
) -> None:
    """Materialize strong-key events and their evidence links (M2)."""
    from ai_security_hot.pipelines.stages import run_cluster_stage

    _setup_logging()
    typer.echo(json.dumps(run_cluster_stage(force=force)))


@app.command("eventize")
def eventize(force: bool = typer.Option(False, help="recompute both M2 stages")) -> None:
    """Run dedupe then event clustering as one operational command."""
    from ai_security_hot.pipelines.stages import run_cluster_stage, run_dedupe_stage

    _setup_logging()
    typer.echo(
        json.dumps(
            {"dedupe": run_dedupe_stage(force=force), "cluster": run_cluster_stage(force=force)}
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
