"""Public frontend aggregation API — no bearer token required.

These endpoints feed the public static pages (index.html). They only read
derived/current data; all mutations live under /ops/.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from ai_security_hot.models.base import session_scope
from ai_security_hot.services.overview import build_overview

router = APIRouter(prefix="/api", tags=["frontend"])


@router.get("/overview")
def overview(
    hot_top_n: int = Query(10, ge=1, le=50),
    per_module_max: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    """Frontend home payload: daily hotspots + module-grouped timelines."""
    with session_scope() as session:
        return build_overview(session, hot_top_n=hot_top_n, per_module_max=per_module_max)
