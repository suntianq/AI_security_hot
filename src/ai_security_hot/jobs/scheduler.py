"""Independent stateless schedules backed by PostgreSQL leases."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

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
        "classify=%ds event=%ds self_check=%ds",
        settings.tick_interval_seconds,
        settings.normalize_interval_seconds,
        settings.fulltext_interval_seconds,
        settings.classification_interval_seconds,
        settings.event_interval_seconds,
        settings.self_check_interval_seconds,
    )
    scheduler.start()
