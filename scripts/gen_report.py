"""Generate a self-contained HTML data report.

Reads current documents + events from PostgreSQL once and embeds them into a
single HTML file with inline CSS/JS (no external deps, no network at view time).
The report shows the data itself — sources, classification tags, event types,
companies, languages, a filterable document table and top events.

Hot spots come from the persistent ``daily_hotspot_items`` snapshots (the same
source the ``/v1/daily-hotspots`` API serves), re-ranked by source count so
multi-source corroborated news outranks single-source filler.

    uv run python scripts/gen_report.py [out.html] [max_document_rows]

DB host port is 5433 (the Docker container); set INTEL_DATABASE_URL or rely on
the default which this script points at 5433.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    AtomicEventEmbedding,
    DocumentEnrichment,
    ExtractedClaim,
    RelationCandidate,
    RelationVerdict,
    SemanticComponentWorkItem,
    SemanticPromotion,
    SemanticRelationComponent,
    SemanticRelationMembership,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import (
    DailyHotspotItem,
    DailyHotspotSnapshot,
    Document,
    Event,
    EventDocument,
    SourceEndpoint,
)
from ai_security_hot.reporting import json_for_html_script

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

# Consumer-electronics / gaming / commerce filler that is not AI×security news.
# Matched against single-source events with no topic label; kept in the
# timeline but excluded from the hot ranking.
# 2026-08-06: added social-news keywords to filter IT之家 crime/ticket spam.
NOISE_KEYWORDS = (
    "发布价",
    "预售",
    "首发价",
    "到手价",
    "优惠",
    "立减",
    "评测",
    "掌机",
    "手机壳",
    "充电器",
    "电视",
    "冰箱",
    "洗衣机",
    "空调",
    "剃须刀",
    "牙刷",
    "音箱",
    "耳机",
    "主板",
    "显卡",
    "固态硬盘",
    "键盘",
    "鼠标",
    "显示器",
    "游戏本",
    "笔记本",
    "奖杯",
    "皮肤",
    "版本更新",
    "返场",
    "商城",
    # Social news filler from IT之家 (crime/ticket/entertainment)
    "网警",
    "警方",
    "落网",
    "犯罪团伙",
    "犯罪嫌疑人",
    "倒卖",
    "黄牛",
    "演唱会",
    "门票",
    "景区门票",
    "代抢",
    "抓获",
)

HOTSPOT_LOOKBACK_DAYS = 7
HOTSPOT_TOP_N = 100

MAX_ROWS_DEFAULT = 4000


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _clean_summary(text: str | None, limit: int = 400) -> str:
    """Strip HTML tags and truncate to a sentence boundary."""
    if not text:
        return ""
    import re
    clean = re.sub(r"<[^>]+>", "", text).strip()
    if len(clean) <= limit:
        return clean
    snippet = clean[:limit]
    for sep in ("\u3002", "\uff01", "\uff1f", ". ", "! ", "? "):
        idx = snippet.rfind(sep)
        if idx > 50:
            return snippet[: idx + 1]
    return snippet.rstrip() + "…"


def _is_noise(payload: dict) -> bool:
    """True for single-source consumer/gaming filler without an AI topic."""
    if (payload.get("source_count") or 0) > 1:
        return False  # multi-source corroborated — worth showing
    if payload.get("topic"):
        return False  # classified into an AI×security topic
    title = (payload.get("title") or "").lower()
    return any(kw in title for kw in NOISE_KEYWORDS)






def _epoch_seconds(iso_value: str | None) -> float:
    """Parse an ISO timestamp to epoch seconds for sorting; 0 when absent."""
    if not iso_value:
        return 0.0
    try:
        return datetime.fromisoformat(iso_value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0

def _cve_from_fingerprint(fingerprint: str | None) -> str | None:
    """Extract the CVE id from an event fingerprint like cve-nvd:CVE-2026-1234."""
    if not fingerprint:
        return None
    match = re.search(r"(CVE-\d{4}-\d{4,})", fingerprint)
    return match.group(1) if match else None

def collect(session, max_rows: int) -> dict[str, Any]:
    # only current, published documents (hide superseded/withdrawn/retired/rejected)
    visible = (Document.source_status == "active") & (Document.record_status == "published")

    total = session.execute(select(func.count()).select_from(Document).where(visible)).scalar_one()
    total_bulk = session.execute(
        select(func.count())
        .select_from(Document)
        .where(visible, Document.endpoint_id.in_(BULK_SOURCES))
    ).scalar_one()

    # aggregates (computed in SQL over the whole visible set)
    src_rows = session.execute(
        select(Document.endpoint_id, func.count())
        .where(visible)
        .group_by(Document.endpoint_id)
        .order_by(desc(func.count()))
    ).all()
    etype_rows = session.execute(
        select(Document.classified_event_type, func.count())
        .where(visible)
        .group_by(Document.classified_event_type)
        .order_by(desc(func.count()))
    ).all()
    lang_rows = session.execute(
        select(Document.language, func.count())
        .where(visible)
        .group_by(Document.language)
        .order_by(desc(func.count()))
    ).all()

    # multi-label tags need per-row expansion — do it in Python over a capped scan
    tech_c: Counter = Counter()
    company_c: Counter = Counter()
    for td, cm in session.execute(
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
                "summary": _clean_summary(d.body_text, 400),
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

    # --- Hot spots: merged recent daily snapshots, re-ranked by source count ---
    # Same source the /v1/daily-hotspots API serves; multi-source corroborated
    # news outranks single-source filler. Noise (consumer/gaming) is demoted.
    hotspot_lookback = datetime.now(UTC) - timedelta(days=HOTSPOT_LOOKBACK_DAYS)
    snapshots = session.execute(
        select(DailyHotspotSnapshot)
        .where(
            DailyHotspotSnapshot.generated_at >= hotspot_lookback,
            DailyHotspotSnapshot.category.in_(("general", "all")),
        )
        .order_by(desc(DailyHotspotSnapshot.generated_at))
    ).scalars().all()
    snapshot_ids = [s.id for s in snapshots]
    events: list[dict] = []
    seen_event_ids: set[int] = set()
    if snapshot_ids:
        items = session.execute(
            select(DailyHotspotItem)
            .where(DailyHotspotItem.snapshot_id.in_(snapshot_ids))
            .order_by(DailyHotspotItem.rank)
        ).scalars()
        for item in items:
            payload = dict(item.payload)
            event_id = int(payload.get("id") or 0)
            if not event_id or event_id in seen_event_ids:
                continue  # dedupe across snapshot revisions
            # Exclude vuln-db (NVD/KEV) and CVE-topic entries from the reading
            # hot list — CVE content is tracked separately.
            category = payload.get("category")
            topic = payload.get("topic")
            if category == "vuln_db" or topic == "cve":
                continue
            seen_event_ids.add(event_id)
            events.append(
                {
                    "id": event_id,
                    "title": payload.get("title") or "",
                    "summary": _clean_summary(payload.get("summary"), 500),
                    "type": payload.get("event_type"),
                    "topic": topic,
                    "score": payload.get("score") or 0,
                    "source_count": int(payload.get("source_count") or 0),
                    "document_count": int(payload.get("document_count") or 0),
                    "evidence_level": payload.get("evidence_level"),
                    "last": payload.get("last_seen_at"),
                    "noise": _is_noise(payload),
                    "_sort_ts": _epoch_seconds(payload.get("last_seen_at")),
                }
            )
    # Re-rank: multi-source first, then score, then recency. Noise sinks to
    # the bottom (kept for the timeline, excluded from the Top N). Timestamps
    # are ISO strings (sortable) with None treated as empty (oldest).
    events.sort(
        key=lambda e: (
            e["noise"],  # False (non-noise) sorts before True
            -(e["source_count"]),
            -(e["score"] or 0),
            -e["_sort_ts"],  # newest first
        )
    )

    # Evidence chains for the Top hot events (docs behind each event).
    top_events = [e for e in events if not e["noise"]][:50]
    event_ids = [e["id"] for e in top_events]
    evidence_by_event: dict[int, list[dict]] = {}
    if event_ids:
        rows = session.execute(
            select(
                EventDocument.event_id,
                Document.title_original,
                Document.canonical_url,
                EventDocument.evidence_level,
                EventDocument.stance,
            )
            .join(Document, Document.id == EventDocument.document_id)
            .where(EventDocument.event_id.in_(event_ids))
            .order_by(EventDocument.event_id, EventDocument.evidence_level)
        ).all()
        for row in rows:
            evidence_by_event.setdefault(int(row.event_id), []).append(
                {
                    "title": row.title_original,
                    "url": row.canonical_url,
                    "level": row.evidence_level,
                    "stance": row.stance,
                }
            )
    for e in top_events:
        e["evidence"] = evidence_by_event.get(e["id"], [])

    # --- CVE focus: recent vuln-db events with their CVE ids (separate block) ---
    cve_focus = []
    cve_cutoff = datetime.now(UTC) - timedelta(days=HOTSPOT_LOOKBACK_DAYS)
    cve_stmt = (
        select(Event, func.count(EventDocument.id))
        .join(EventDocument, EventDocument.event_id == Event.id)
        .where(
            Event.status == "detected",
            Event.category == "vuln_db",
            Event.last_seen_at >= cve_cutoff,
        )
        .group_by(Event.id)
        .order_by(desc(Event.last_seen_at))
        .limit(30)
    )
    for e, ndocs in session.execute(cve_stmt):
        cve_focus.append(
            {
                "title": e.title,
                "fingerprint": e.fingerprint,
                "cve": _cve_from_fingerprint(e.fingerprint),
                "score": e.score,
                "docs": ndocs,
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

    # --- source health: endpoints by status + failure counts ---
    ep_status_rows = session.execute(
        select(SourceEndpoint.status, func.count())
        .group_by(SourceEndpoint.status)
        .order_by(desc(func.count()))
    ).all()
    degraded_eps = session.execute(
        select(SourceEndpoint.id, SourceEndpoint.status, SourceEndpoint.consecutive_failures)
        .where(
            SourceEndpoint.status.in_(["degraded", "failed", "paused"]),
            SourceEndpoint.enabled.is_(True),
        )
        .order_by(desc(SourceEndpoint.consecutive_failures))
        .limit(15)
    ).all()

    # --- semantic enrichment summary (M2.2) ---
    sem_total = session.execute(select(func.count()).select_from(DocumentEnrichment)).scalar_one()
    sem_relevant = session.execute(
        select(func.count())
        .select_from(DocumentEnrichment)
        .where(DocumentEnrichment.relevant.is_(True))
    ).scalar_one()
    sem_with_batch = session.execute(
        select(func.count())
        .select_from(DocumentEnrichment)
        .where(DocumentEnrichment.batch_id.is_not(None))
    ).scalar_one()
    sem_with_usage = session.execute(
        select(func.count()).select_from(DocumentEnrichment).where(DocumentEnrichment.usage != {})
    ).scalar_one()
    sem_finish_reason = session.execute(
        select(func.count())
        .select_from(DocumentEnrichment)
        .where(DocumentEnrichment.finish_reason.is_not(None))
    ).scalar_one()
    sem_ct_rows = session.execute(
        select(DocumentEnrichment.content_type, func.count())
        .group_by(DocumentEnrichment.content_type)
        .order_by(desc(func.count()))
    ).all()
    sem_atomic = session.execute(select(func.count()).select_from(AtomicEvent)).scalar_one()
    sem_claims = session.execute(select(func.count()).select_from(ExtractedClaim)).scalar_one()
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
    active_components = session.execute(
        select(func.count())
        .select_from(SemanticRelationComponent)
        .where(SemanticRelationComponent.status == "active")
    ).scalar_one()
    active_memberships = session.execute(
        select(func.count())
        .select_from(SemanticRelationMembership)
        .where(SemanticRelationMembership.active.is_(True))
    ).scalar_one()
    component_work_rows = session.execute(
        select(SemanticComponentWorkItem.status, func.count())
        .group_by(SemanticComponentWorkItem.status)
        .order_by(desc(func.count()))
    ).all()
    promotion_rows = session.execute(
        select(SemanticPromotion.status, func.count())
        .group_by(SemanticPromotion.status)
        .order_by(desc(func.count()))
    ).all()
    embedding_total = session.execute(
        select(func.count()).select_from(AtomicEventEmbedding)
    ).scalar_one()
    embedding_versions = session.execute(
        select(func.count(func.distinct(AtomicEventEmbedding.execution_version)))
    ).scalar_one()
    embedding_candidate_rows = session.execute(
        select(RelationCandidate.status, func.count())
        .where(RelationCandidate.embedding_score.is_not(None))
        .group_by(RelationCandidate.status)
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
        "active_components": active_components,
        "active_memberships": active_memberships,
        "component_work_status": {(k or "?"): v for k, v in component_work_rows},
        "promotions": {(k or "?"): v for k, v in promotion_rows},
        "embeddings": int(embedding_total),
        "embedding_versions": int(embedding_versions),
        "embedding_candidates": {(k or "?"): v for k, v in embedding_candidate_rows},
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
            "hotspots": len([e for e in events if not e["noise"]]),
        },
        "sources": [{"id": k, "n": v} for k, v in src_rows],
        "tech": dict(tech_c.most_common()),
        "company": dict(company_c.most_common()),
        "etype": {(k or "opinion"): v for k, v in etype_rows},
        "lang": {(k or "?"): v for k, v in lang_rows},
        "docs": docs,
        "events": events,
        "cve_focus": cve_focus,
        "source_health": {
            "by_status": {(k or "?"): v for k, v in ep_status_rows},
            "degraded": [
                {"id": ep.id, "status": ep.status, "failures": ep.consecutive_failures}
                for ep in degraded_eps
            ],
        },
        "semantic": sem,
        "labels": {"tech": TECH_LABELS, "etype": ETYPE_LABELS, "source": SOURCE_LABELS},
        "bulkSources": sorted(BULK_SOURCES),
        "hotspot": {"lookback_days": HOTSPOT_LOOKBACK_DAYS, "top_n": HOTSPOT_TOP_N},
    }


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("report.html")
    max_rows = int(sys.argv[2]) if len(sys.argv) > 2 else MAX_ROWS_DEFAULT
    with session_scope() as session:
        data = collect(session, max_rows)
    payload = json_for_html_script(data)
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
