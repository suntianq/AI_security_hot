"""Daily content archive — freeze each natural day's overview for history.

Unlike ``daily_hotspot_snapshots`` (which keep only the top-N events), this
freezes the *full* overview payload — hotspots plus every module timeline — so
the frontend can browse what each day actually looked like. Generation is
idempotent per date (content-hash guarded).
"""

from __future__ import annotations

import json
from datetime import date
from hashlib import sha256
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_security_hot.models.tables import DailyArchive
from ai_security_hot.services.overview import build_overview


def _digest(payload: dict) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def generate_daily_archive(
    session: Session,
    natural_date: date,
    *,
    per_module_max: int = 200,
) -> DailyArchive:
    """Build and freeze the overview for a date; no-op if content unchanged."""
    payload = build_overview(
        session, per_module_max=per_module_max, natural_date=natural_date
    )
    digest = _digest(payload)
    existing = session.execute(
        select(DailyArchive).where(DailyArchive.natural_date == natural_date)
    ).scalar_one_or_none()
    if existing is not None and existing.content_hash == digest:
        return existing
    if existing is not None:
        session.delete(existing)
        session.flush()
    archive = DailyArchive(
        natural_date=natural_date,
        content_hash=digest,
        payload=payload,
    )
    session.add(archive)
    session.flush()
    return archive


def list_archive_dates(session: Session) -> list[str]:
    """Natural dates with a frozen archive, newest first."""
    rows = session.execute(
        select(DailyArchive.natural_date).order_by(DailyArchive.natural_date.desc())
    ).scalars()
    return [str(d) for d in rows]


def get_archive(session: Session, natural_date: date) -> dict[str, Any] | None:
    archive = session.execute(
        select(DailyArchive).where(DailyArchive.natural_date == natural_date)
    ).scalar_one_or_none()
    return dict(archive.payload) if archive is not None else None
