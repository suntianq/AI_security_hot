"""Generate a self-contained HTML report of current classification data.

Reads documents from the DB, embeds them as JSON into a single HTML file with
inline CSS/JS (no external deps, no network). Re-runnable any time.

    uv run python scripts/gen_report.py [out.html] [max_rows]
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import and_, func, not_, select

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, Source, SourceEndpoint
from ai_security_hot.storage import repositories as repo

TECH_LABELS = {
    "cve": "CVE",
    "llm": "LLM",
    "ai_for_security": "AI for Security",
    "security_for_ai": "Security for AI",
    "agent": "Agent",
    "system_security": "系统安全",
}


def _document_payload(d: Document, endpoint: SourceEndpoint, source: Source) -> dict:
    current = repo.is_current_document(d.source_status, d.record_status)
    return {
        "id": d.id,
        "title": d.title_original,
        "url": d.canonical_url,
        "source": source.name,
        "source_id": source.id,
        "endpoint": endpoint.id,
        "endpoint_enabled": endpoint.enabled,
        "endpoint_status": endpoint.status,
        "replacement_endpoint": endpoint.replacement_endpoint_id,
        "source_status": d.source_status,
        "source_status_reason": d.source_status_reason,
        "record_status": d.record_status,
        "record_status_raw": d.record_status_raw,
        "current": current,
        "lang": d.language,
        "published": d.published_at_utc.isoformat() if d.published_at_utc else None,
        "tech": list(d.tech_directions or []),
        "company": list(d.company_models or []),
        "etype": d.classified_event_type,
        "method": d.classify_method,
        "conf": d.classify_confidence,
        "cve": (d.identifiers or {}).get("cve", []),
    }


def collect(max_rows: int = 30000) -> tuple[list[dict], dict]:
    if max_rows < 1000:
        raise ValueError("max_rows must be at least 1000")

    with session_scope() as session:
        current_conditions = repo.current_document_conditions()
        current_clause = and_(*current_conditions)

        total = int(session.scalar(select(func.count()).select_from(Document)) or 0)
        current_total = int(
            session.scalar(select(func.count()).select_from(Document).where(*current_conditions))
            or 0
        )
        historical_total = total - current_total

        tech_c: Counter = Counter()
        etype_c: Counter = Counter()
        company_c: Counter = Counter()
        current_source_c: Counter = Counter()
        stat_rows = session.execute(
            select(
                Document.tech_directions,
                Document.company_models,
                Document.classified_event_type,
                Source.name,
            )
            .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .where(*current_conditions)
            .execution_options(yield_per=2000)
        )
        for directions, companies, event_type, source_name in stat_rows:
            tech_c.update(directions or [])
            company_c.update(companies or [])
            if event_type:
                etype_c[event_type] += 1
            current_source_c[source_name] += 1

        source_status_c = Counter(
            dict(
                session.execute(
                    select(Document.source_status, func.count()).group_by(Document.source_status)
                ).all()
            )
        )
        record_status_c = Counter(
            dict(
                session.execute(
                    select(Document.record_status, func.count()).group_by(Document.record_status)
                ).all()
            )
        )
        all_source_c = Counter(
            dict(
                session.execute(
                    select(Source.name, func.count())
                    .select_from(Document)
                    .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
                    .join(Source, Source.id == SourceEndpoint.source_id)
                    .group_by(Source.name)
                ).all()
            )
        )
        endpoint_c = Counter(
            dict(
                session.execute(
                    select(Document.endpoint_id, func.count()).group_by(Document.endpoint_id)
                ).all()
            )
        )
        endpoint_current_c = Counter(
            dict(
                session.execute(
                    select(Document.endpoint_id, func.count())
                    .where(*current_conditions)
                    .group_by(Document.endpoint_id)
                ).all()
            )
        )

        # A static HTML report must remain browser-sized as NVD grows. Preserve
        # up to 5k non-current evidence rows, then fill the remaining budget with
        # the newest current rows. Aggregate counts above always cover the DB.
        history_limit = min(5000, max_rows // 4)
        history_rows = session.execute(
            select(Document, SourceEndpoint, Source)
            .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .where(not_(current_clause))
            .order_by(Document.id.desc())
            .limit(history_limit)
        ).all()
        current_limit = max_rows - len(history_rows)
        current_rows = session.execute(
            select(Document, SourceEndpoint, Source)
            .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .where(*current_conditions)
            .order_by(Document.id.desc())
            .limit(current_limit)
        ).all()
        docs = [
            _document_payload(document, endpoint, source)
            for document, endpoint, source in [*history_rows, *current_rows]
        ]
        docs.sort(key=lambda item: int(item["id"]), reverse=True)

        endpoints = []
        for endpoint, source in session.execute(
            select(SourceEndpoint, Source)
            .join(Source, Source.id == SourceEndpoint.source_id)
            .order_by(Source.name, SourceEndpoint.id)
        ).all():
            endpoints.append(
                {
                    "id": endpoint.id,
                    "source": source.name,
                    "source_id": source.id,
                    "enabled": endpoint.enabled,
                    "status": endpoint.status,
                    "replacement": endpoint.replacement_endpoint_id,
                    "current_documents": endpoint_current_c[endpoint.id],
                    "all_documents": endpoint_c[endpoint.id],
                }
            )

        embedded_current = sum(1 for document in docs if document["current"])
        stats = {
            "total": total,
            "current_total": current_total,
            "historical_total": historical_total,
            "embedded_total": len(docs),
            "embedded_current": embedded_current,
            "embedded_historical": len(docs) - embedded_current,
            "truncated": len(docs) < total,
            "tech": dict(tech_c.most_common()),
            "etype": dict(etype_c.most_common()),
            "company": dict(company_c.most_common()),
            "source": dict(current_source_c.most_common()),
            "source_all": dict(all_source_c.most_common()),
            "source_status": dict(source_status_c.most_common()),
            "record_status": dict(record_status_c.most_common()),
            "endpoints": endpoints,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        }
        return docs, stats


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("report.html")
    max_rows = int(sys.argv[2]) if len(sys.argv) > 2 else 30000
    docs, stats = collect(max_rows=max_rows)
    payload = json.dumps(
        {"docs": docs, "stats": stats, "techLabels": TECH_LABELS}, ensure_ascii=False
    )
    # This is embedded inside an HTML <script>; source text is untrusted.
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    template = (Path(__file__).parent / "dashboard_template.html").read_text(encoding="utf-8")
    html = template.replace("/*__DATA__*/", payload)
    out.write_text(html, encoding="utf-8")
    print(
        f"wrote {out} — {stats['current_total']} current / "
        f"{stats['total']} total documents, {out.stat().st_size // 1024} KB"
    )


if __name__ == "__main__":
    main()
