"""Independent stateless schedules backed by PostgreSQL leases."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler

from ai_security_hot.config.settings import get_settings
from ai_security_hot.jobs.self_check import run_self_check
from ai_security_hot.models.base import session_scope
from ai_security_hot.pipelines.stages import (
    run_classify_stage,
    run_cluster_stage,
    run_dedupe_stage,
    run_fetch_stage,
    run_fulltext_stage,
    run_normalize_stage,
)
from ai_security_hot.storage import repositories as repo

log = logging.getLogger("intel.scheduler")


def worker_heartbeat_tick() -> None:
    """Prove that APScheduler is still dispatching jobs inside the container."""
    heartbeat_file = Path(get_settings().worker_heartbeat_file)
    heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
    heartbeat_file.touch()


def fetch_tick() -> None:
    """Network polling only; long source pagination cannot block local stages."""
    try:
        log.info("fetch_tick: %s", run_fetch_stage())
    except Exception:
        log.exception("fetch_tick failed")


def normalize_tick() -> None:
    """Drain immutable raw evidence independently from network fetch latency."""
    try:
        settings = get_settings()
        log.info(
            "normalize_tick: %s",
            run_normalize_stage(limit=settings.normalize_batch_size),
        )
    except Exception:
        log.exception("normalize_tick failed")


def fulltext_tick() -> None:
    """Bounded second-fetch work, isolated from both feed polling and parsing."""
    try:
        settings = get_settings()
        log.info(
            "fulltext_tick: %s",
            run_fulltext_stage(limit=settings.fulltext_batch_size),
        )
    except Exception:
        log.exception("fulltext_tick failed")


def ingest_tick() -> None:
    """Backward-compatible manual pass; worker schedules each stage separately."""
    fetch_tick()
    normalize_tick()
    fulltext_tick()


def classify_tick() -> None:
    """Bounded slow-model work with its own lease and scheduler instance."""
    try:
        log.info("classify_tick: %s", run_classify_stage())
    except Exception:
        log.exception("classify_tick failed")


def semantic_tick() -> None:
    """Cost-bounded semantic extraction; always shadow-only in M2.2."""
    try:
        from ai_security_hot.pipelines.semantic_stage import run_semantic_enrichment_stage

        log.info("semantic_tick: %s", run_semantic_enrichment_stage())
    except Exception:
        log.exception("semantic_tick failed")


def embedding_tick() -> None:
    """Generate bounded vectors and recall candidates without auto-merging."""
    try:
        from ai_security_hot.embeddings.pipeline import run_embedding_stage

        log.info("embedding_tick: %s", run_embedding_stage())
    except Exception:
        log.exception("embedding_tick failed")


def relation_tick() -> None:
    """Advance and drain the durable M2.3 candidate queue in bounded batches."""
    try:
        from ai_security_hot.semantic.candidate_scan import run_incremental_relation_scan
        from ai_security_hot.semantic.components import run_component_stage

        settings = get_settings()
        limit = settings.relation_scan_batch_size
        relation_summary = run_incremental_relation_scan(
            seed_limit=limit, pair_limit=limit * 5, work_limit=limit
        )
        component_summary = run_component_stage(
            discovery_limit=limit * 5,
            work_limit=limit,
            max_atomic_events=settings.m2_max_local_documents,
        )
        log.info(
            "relation_tick: relations=%s components=%s",
            relation_summary,
            component_summary,
        )
    except Exception:
        log.exception("relation_tick failed")


def daily_snapshot_tick() -> None:
    """Freeze current and previous natural-day rankings; unchanged content is a no-op.

    Generates separate ``general`` and ``vuln_db`` snapshots so the reading
    hotspot ranking is never flooded by high-score NVD CVE entries — the news
    and the vulnerability database keep independent score paths.
    """
    try:
        from ai_security_hot.snapshots import generate_daily_snapshot

        settings = get_settings()
        timezone = ZoneInfo(settings.daily_snapshot_timezone)
        today = datetime.now(timezone).date()
        results = []
        with session_scope() as session:
            for natural_date in (today - timedelta(days=1), today):
                for category in ("general", "vuln_db"):
                    row = generate_daily_snapshot(
                        session,
                        natural_date=natural_date,
                        timezone=settings.daily_snapshot_timezone,
                        category=category,
                        limit=settings.daily_snapshot_limit,
                    )
                    results.append(
                        (natural_date.isoformat(), category, int(row.id), int(row.revision))
                    )
        log.info("daily_snapshot_tick: %s", results)
    except Exception:
        log.exception("daily_snapshot_tick failed")


def daily_archive_tick() -> None:
    """Freeze today's full content overview for the daily history archive.

    Generates (or refreshes, if content changed) the archive for yesterday and
    today so the frontend daily page always has the latest day available.
    """
    try:
        from ai_security_hot.services.daily_archive import generate_daily_archive

        settings = get_settings()
        timezone = ZoneInfo(settings.daily_snapshot_timezone)
        today = datetime.now(timezone).date()
        results = []
        with session_scope() as session:
            for natural_date in (today - timedelta(days=1), today):
                row = generate_daily_archive(session, natural_date)
                results.append((natural_date.isoformat(), row.content_hash[:12]))
        log.info("daily_archive_tick: %s", results)
    except Exception:
        log.exception("daily_archive_tick failed")


def event_tick() -> None:
    """Versioned derived-data stages, independent from fetch and classification."""
    try:
        settings = get_settings()
        with session_scope() as session:
            backlog = repo.count_event_pipeline_backlog(session)
        threshold = settings.event_backlog_threshold
        if threshold > 0 and backlog > threshold:
            log.info(
                "event_tick deferred: m1_backlog=%d threshold=%d",
                backlog,
                threshold,
            )
            return
        stats = {"dedupe": run_dedupe_stage(), "cluster": run_cluster_stage()}
        log.info("event_tick: %s", stats)
    except Exception:
        log.exception("event_tick failed")


def tick() -> None:
    """Backward-compatible manual all-stage pass; worker uses split jobs."""
    ingest_tick()
    classify_tick()
    event_tick()


def run_worker() -> None:
    settings = get_settings()
    scheduler = BlockingScheduler(timezone="Asia/Shanghai")
    first_run = datetime.now(UTC)
    worker_heartbeat_tick()
    scheduler.add_job(
        worker_heartbeat_tick,
        "interval",
        seconds=30,
        id="worker_heartbeat",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        fetch_tick,
        "interval",
        seconds=settings.tick_interval_seconds,
        id="fetch",
        max_instances=1,
        coalesce=True,
        next_run_time=first_run,
    )
    scheduler.add_job(
        normalize_tick,
        "interval",
        seconds=settings.normalize_interval_seconds,
        id="normalize",
        max_instances=1,
        coalesce=True,
        next_run_time=first_run,
    )
    scheduler.add_job(
        fulltext_tick,
        "interval",
        seconds=settings.fulltext_interval_seconds,
        id="fulltext",
        max_instances=1,
        coalesce=True,
        next_run_time=first_run,
    )
    scheduler.add_job(
        classify_tick,
        "interval",
        seconds=settings.classification_interval_seconds,
        id="classify",
        max_instances=1,
        coalesce=True,
        next_run_time=first_run,
    )
    if settings.semantic_enrichment_enabled:
        scheduler.add_job(
            semantic_tick,
            "interval",
            seconds=settings.semantic_enrichment_interval_seconds,
            id="semantic_enrichment",
            max_instances=1,
            coalesce=True,
            next_run_time=first_run,
        )
    if settings.embedding_enabled:
        scheduler.add_job(
            embedding_tick,
            "interval",
            seconds=settings.embedding_interval_seconds,
            id="embedding",
            max_instances=1,
            coalesce=True,
            next_run_time=first_run,
        )
    if settings.relation_scan_enabled:
        scheduler.add_job(
            relation_tick,
            "interval",
            seconds=settings.relation_scan_interval_seconds,
            id="relation_scan",
            max_instances=1,
            coalesce=True,
            next_run_time=first_run,
        )
    if settings.daily_snapshot_enabled:
        scheduler.add_job(
            daily_snapshot_tick,
            "interval",
            seconds=settings.daily_snapshot_interval_seconds,
            id="daily_snapshot",
            max_instances=1,
            coalesce=True,
            next_run_time=first_run,
        )
        scheduler.add_job(
            daily_archive_tick,
            "interval",
            seconds=settings.daily_snapshot_interval_seconds,
            id="daily_archive",
            max_instances=1,
            coalesce=True,
            next_run_time=first_run,
        )
    scheduler.add_job(
        event_tick,
        "interval",
        seconds=settings.event_interval_seconds,
        id="event",
        max_instances=1,
        coalesce=True,
        next_run_time=first_run,
    )
    scheduler.add_job(
        run_self_check,
        "interval",
        seconds=settings.self_check_interval_seconds,
        id="self_check",
        max_instances=1,
        coalesce=True,
    )
    log.info(
        "worker started: fetch=%ds normalize=%ds fulltext=%ds "
        "classify=%ds semantic=%s embedding=%s relation=%s snapshot=%s event=%ds self_check=%ds",
        settings.tick_interval_seconds,
        settings.normalize_interval_seconds,
        settings.fulltext_interval_seconds,
        settings.classification_interval_seconds,
        "on" if settings.semantic_enrichment_enabled else "off",
        "on" if settings.embedding_enabled else "off",
        "on" if settings.relation_scan_enabled else "off",
        "on" if settings.daily_snapshot_enabled else "off",
        settings.event_interval_seconds,
        settings.self_check_interval_seconds,
    )
    scheduler.start()
