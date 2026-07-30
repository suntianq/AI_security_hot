"""Self-check job (MVP 16 / plan): surface silent failures.

Flags endpoints that are stale (no success within N intervals), degraded
(consecutive failures), or stuck (raw items leased in a stage for too long).
In M0 it logs a structured report; wiring to an alert channel is a later step.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import func, select

from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.events.intelligence import CLUSTER_VERSION, DEDUPE_VERSION
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, Event, RawItem, SourceEndpoint

log = logging.getLogger("intel.self_check")


def run_self_check() -> dict:
    now = datetime.now(UTC)
    report: dict = {
        "stale": [],
        "degraded": [],
        "stuck_items": 0,
        "event_pipeline": {},
    }

    with session_scope() as session:
        endpoints = (
            session.execute(select(SourceEndpoint).where(SourceEndpoint.enabled.is_(True)))
            .scalars()
            .all()
        )

        for ep in endpoints:
            if ep.status == "degraded" or ep.consecutive_failures >= 3:
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
                RawItem.stage.notin_(
                    [
                        PipelineStage.NORMALIZED.value,
                        PipelineStage.DONE.value,
                        PipelineStage.FAILED.value,
                    ]
                ),
                RawItem.stage_lease_until < now,
            )
        ).scalar_one()
        report["stuck_items"] = int(stuck)
        dedupe_due = session.execute(
            select(func.count())
            .select_from(Document)
            .where(Document.dedupe_version.is_(None) | (Document.dedupe_version != DEDUPE_VERSION))
        ).scalar_one()
        cluster_due = session.execute(
            select(func.count())
            .select_from(Document)
            .where(
                Document.dedupe_version == DEDUPE_VERSION,
                Document.cluster_version.is_(None) | (Document.cluster_version != CLUSTER_VERSION),
            )
        ).scalar_one()
        events = session.execute(
            select(func.count()).select_from(Event).where(Event.status == "detected")
        ).scalar_one()
        report["event_pipeline"] = {
            "dedupe_due": int(dedupe_due),
            "cluster_due": int(cluster_due),
            "events": int(events),
        }

    if report["degraded"] or report["stale"] or report["stuck_items"]:
        log.warning("self_check found issues: %s", report)
    else:
        log.info("self_check ok: all endpoints healthy")
    return report
