"""Generate a self-contained HTML data report.

Reads current documents + events from PostgreSQL once and embeds them into a
single HTML file with inline CSS/JS (no external deps, no network at view time).
The report shows the data itself — sources, classification tags, event types,
companies, languages, a filterable document table and top events.

    uv run python scripts/gen_report.py [out.html] [max_document_rows]

DB host port is 5433 (the Docker container); set INTEL_DATABASE_URL or rely on
the default which this script points at 5433.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    DocumentEnrichment,
    ExtractedClaim,
    RelationVerdict,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import Document, Event, SourceEndpoint

# Friendly labels for the two-layer taxonomy (keeps the report readable).
TECH_LABELS = {
    "cve": "CVE 漏洞",
    "llm": "大模型",
    "ai_for_security": "AI 用于安全",
    "security_for_ai": "AI 自身安全",
    "agent": "智能体",
    "system_security": "系统安全",
}
ETYPE_LABELS = {
    "vulnerability": "漏洞",
    "release": "发布",
    "research": "研究",
    "incident": "事故",
    "policy": "政策",
    "funding": "融资",
    "tool": "工具",
    "opinion": "观点/其他",
}
SOURCE_LABELS = {
    "openai-news-rss": "OpenAI News",
    "aihot-selected-api": "AI HOT 精选",
    "aihot-selected-rss": "AI HOT (RSS)",
    "cisa-kev": "CISA KEV",
    "anthropic-news": "Anthropic",
    "nvd-recent": "NVD 漏洞库",
    "huggingface-blog-rss": "Hugging Face",
    "google-security-rss": "Google Security",
    "trailofbits-rss": "Trail of Bits",
    "portswigger-research-rss": "PortSwigger",
    "apple-ml-research-rss": "Apple ML",
    "nvidia-blog-rss": "NVIDIA",
    "wiz-blog-rss": "Wiz",
    "arxiv-ai-llm": "arXiv AI/LLM",
    "arxiv-security-ai": "arXiv 安全",
    "hackernews-rss": "Hacker News",
    "ithome-rss": "IT之家",
    "google-blog-ai-rss": "Google Blog AI",
    "github-trending-rss": "GitHub Trending",
}

# Sources that are bulk vulnerability feeds — huge volume, low reading value.
# The report tags them so the UI can offer a one-click toggle.
BULK_SOURCES = {"nvd-recent"}

MAX_ROWS_DEFAULT = 4000


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def collect(session, max_rows: int) -> dict[str, Any]:
    # only current, published documents (hide superseded/withdrawn/retired/rejected)
    visible = (
        (Document.source_status == "active")
        & (Document.record_status == "published")
    )

    total = session.execute(
        select(func.count()).select_from(Document).where(visible)
    ).scalar_one()
    total_bulk = session.execute(
        select(func.count()).select_from(Document).where(
            visible, Document.endpoint_id.in_(BULK_SOURCES)
        )
    ).scalar_one()

    # aggregates (computed in SQL over the whole visible set)
    src_rows = session.execute(
        select(Document.endpoint_id, func.count())
        .where(visible).group_by(Document.endpoint_id).order_by(desc(func.count()))
    ).all()
    etype_rows = session.execute(
        select(Document.classified_event_type, func.count())
        .where(visible).group_by(Document.classified_event_type).order_by(desc(func.count()))
    ).all()
    lang_rows = session.execute(
        select(Document.language, func.count())
        .where(visible).group_by(Document.language).order_by(desc(func.count()))
    ).all()

    # multi-label tags need per-row expansion — do it in Python over a capped scan
    tech_c: Counter = Counter()
    company_c: Counter = Counter()
    for (td, cm) in session.execute(
        select(Document.tech_directions, Document.company_models).where(visible)
    ):
        for t in td or []:
            tech_c[t] += 1
        for c in cm or []:
            company_c[c] += 1

    # sample rows for the table — newest first, exclude bulk vuln feed by default
    # (the UI still lets the user include it). We cap to keep the file small.
    sample_stmt = (
        select(Document)
        .where(visible, Document.endpoint_id.notin_(BULK_SOURCES))
        .order_by(desc(Document.published_at_utc).nullslast(), desc(Document.id))
        .limit(max_rows)
    )
    docs = []
    for d in session.execute(sample_stmt).scalars():
        docs.append(
            {
                "title": d.title_original,
                "url": d.canonical_url,
                "source": d.endpoint_id,
                "lang": d.language,
                "pub": _iso(d.published_at_utc),
                "tech": d.tech_directions or [],
                "company": d.company_models or [],
                "etype": d.classified_event_type,
                "cve": (d.identifiers or {}).get("cve", []),
                "dup": d.near_dup_of is not None,
            }
        )

    # top recent general (non-vuln) events by score.
    # Vuln-db events (NVD/KEV category) and any CVE-topic event (including news
    # articles about CVEs) are excluded from the reader-facing hot list — CVE
    # content is tracked separately.
    events = []
    ev_stmt = (
        select(Event)
        .where(
            Event.status == "detected",
            (Event.category == "general") | (Event.category.is_(None)),
            (Event.topic != "cve") | (Event.topic.is_(None)),
        )
        .order_by(desc(Event.score).nullslast(), desc(Event.last_seen_at).nullslast())
        .limit(200)
    )
    for e in session.execute(ev_stmt).scalars():
        events.append(
            {
                "title": e.title,
                "type": e.event_type,
                "topic": e.topic,
                "score": e.score,
                "last": _iso(e.last_seen_at),
            }
        )

    # general (non-vuln-db) events count; vuln_db events are tracked separately.
    total_events = session.execute(
        select(func.count())
        .select_from(Event)
        .where(
            Event.status == "detected",
            (Event.category == "general") | (Event.category.is_(None)),
        )
    ).scalar_one()
    total_cve_events = session.execute(
        select(func.count())
        .select_from(Event)
        .where(Event.status == "detected", Event.category == "vuln_db")
    ).scalar_one()
    active_sources = session.execute(
        select(func.count()).select_from(SourceEndpoint).where(SourceEndpoint.enabled.is_(True))
    ).scalar_one()

    # --- semantic enrichment summary (M2.2) ---
    sem_total = session.execute(
        select(func.count()).select_from(DocumentEnrichment)
    ).scalar_one()
    sem_relevant = session.execute(
        select(func.count()).select_from(DocumentEnrichment).where(
            DocumentEnrichment.relevant.is_(True)
        )
    ).scalar_one()
    sem_with_batch = session.execute(
        select(func.count()).select_from(DocumentEnrichment).where(
            DocumentEnrichment.batch_id.is_not(None)
        )
    ).scalar_one()
    sem_with_usage = session.execute(
        select(func.count()).select_from(DocumentEnrichment).where(
            DocumentEnrichment.usage != {}
        )
    ).scalar_one()
    sem_finish_reason = session.execute(
        select(func.count()).select_from(DocumentEnrichment).where(
            DocumentEnrichment.finish_reason.is_not(None)
        )
    ).scalar_one()
    sem_ct_rows = session.execute(
        select(DocumentEnrichment.content_type, func.count())
        .group_by(DocumentEnrichment.content_type)
        .order_by(desc(func.count()))
    ).all()
    sem_atomic = session.execute(
        select(func.count()).select_from(AtomicEvent)
    ).scalar_one()
    sem_claims = session.execute(
        select(func.count()).select_from(ExtractedClaim)
    ).scalar_one()
    sem_work_status = session.execute(
        select(SemanticWorkItem.status, func.count())
        .group_by(SemanticWorkItem.status)
        .order_by(desc(func.count()))
    ).all()
    # per-source enrichment distribution (exposes the source-skew M2.2.2 fixes)
    sem_src_rows = session.execute(
        select(Document.endpoint_id, func.count())
        .join(DocumentEnrichment, DocumentEnrichment.document_id == Document.id)
        .group_by(Document.endpoint_id)
        .order_by(desc(func.count()))
    ).all()
    # M2.3 relation verdicts + M2.4 promotion metrics (shadow)
    relation_rows = session.execute(
        select(RelationVerdict.decision, func.count())
        .group_by(RelationVerdict.decision)
        .order_by(desc(func.count()))
    ).all()
    sem = {
        "total": sem_total,
        "relevant": sem_relevant,
        "irrelevant": sem_total - sem_relevant,
        "with_batch": sem_with_batch,
        "with_usage": sem_with_usage,
        "with_finish_reason": sem_finish_reason,
        "content_types": {(k or "?"): v for k, v in sem_ct_rows},
        "by_source": {(k or "?"): v for k, v in sem_src_rows},
        "atomic_events": sem_atomic,
        "claims": sem_claims,
        "work_status": {(k or "?"): v for k, v in sem_work_status},
        "relations": {(k or "?"): v for k, v in relation_rows},
    }

    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "totals": {
            "documents": total,
            "documents_bulk": total_bulk,
            "documents_reading": total - total_bulk,
            "events": total_events,
            "cve_events": total_cve_events,
            "sources": active_sources,
            "sample": len(docs),
        },
        "sources": [{"id": k, "n": v} for k, v in src_rows],
        "tech": dict(tech_c.most_common()),
        "company": dict(company_c.most_common()),
        "etype": {(k or "opinion"): v for k, v in etype_rows},
        "lang": {(k or "?"): v for k, v in lang_rows},
        "docs": docs,
        "events": events,
        "semantic": sem,
        "labels": {"tech": TECH_LABELS, "etype": ETYPE_LABELS, "source": SOURCE_LABELS},
        "bulkSources": sorted(BULK_SOURCES),
    }


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("report.html")
    max_rows = int(sys.argv[2]) if len(sys.argv) > 2 else MAX_ROWS_DEFAULT
    with session_scope() as session:
        data = collect(session, max_rows)
    payload = json.dumps(data, ensure_ascii=False)
    template = (Path(__file__).parent / "report_template.html").read_text(encoding="utf-8")
    html = template.replace("/*__DATA__*/", payload)
    out.write_text(html, encoding="utf-8")
    t = data["totals"]
    print(
        f"wrote {out} — {t['documents']} docs "
        f"({t['documents_reading']} reading + {t['documents_bulk']} bulk), "
        f"{t['events']} events, {out.stat().st_size // 1024} KB"
    )


if __name__ == "__main__":
    main()
