"""Stateless scheduler (plan 修正 5).

APScheduler only fires a stateless ``tick`` on an interval; the real due-time,
lease and results live in PostgreSQL. Restart has no window, and a second
instance is safe because claiming uses FOR UPDATE SKIP LOCKED.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from ai_security_hot.config.settings import get_settings
from ai_security_hot.jobs.self_check import run_self_check
from ai_security_hot.pipelines.stages import (
    run_classify_stage,
    run_fetch_stage,
    run_fulltext_stage,
    run_normalize_stage,
)

log = logging.getLogger("intel.scheduler")


def tick() -> None:
    """One scheduler tick: run each stage runner once over its due work."""
    try:
        fetch_stats = run_fetch_stage()
        norm_stats = run_normalize_stage()
        ft_stats = run_fulltext_stage()
        cls_stats = run_classify_stage()
        log.info(
            "tick: fetch=%s normalize=%s fulltext=%s classify=%s",
            fetch_stats, norm_stats, ft_stats, cls_stats,
        )
    except Exception:
        log.exception("tick failed")


def run_worker() -> None:
    settings = get_settings()
    scheduler = BlockingScheduler(timezone="Asia/Shanghai")
    scheduler.add_job(
        tick, "interval", seconds=settings.tick_interval_seconds, id="tick",
        max_instances=1, coalesce=True,
    )
    scheduler.add_job(
        run_self_check, "interval", seconds=settings.self_check_interval_seconds,
        id="self_check", max_instances=1, coalesce=True,
    )
    log.info(
        "worker started: tick=%ds self_check=%ds",
        settings.tick_interval_seconds, settings.self_check_interval_seconds,
    )
    tick()  # run once immediately on startup
    scheduler.start()
