"""Frontend overview service.

Produces the data the public frontend needs in one query pass — the daily
hotspots (multi-source first, general news only) plus module-grouped timelines
(news / papers / cve / trending). This is the same read logic the
old ``scripts/gen_daily.py`` used, now served over the API so the frontend is a
live page instead of a regenerated HTML file.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ai_security_hot.config.cve_follow import is_followed_cve
from ai_security_hot.domain.enums import STRUCTURED_VULN_ENDPOINTS
from ai_security_hot.models.tables import (
    DailyHotspotItem,
    DailyHotspotSnapshot,
    Document,
    RawItem,
    Source,
    SourceEndpoint,
)

SOURCE_LABELS = {
    "openai-news-rss": "OpenAI News",
    "aihot-selected-api": "AI HOT",
    "aihot-selected-rss": "AI HOT (RSS)",
    "cisa-kev": "CISA KEV",
    "anthropic-news": "Anthropic",
    "nvd-recent": "NVD",
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
    "hackernews-api": "Hacker News",
    "ithome-rss": "IT之家",
    "google-blog-ai-rss": "Google Blog AI",
    "github-trending-rss": "GitHub Trending",
}

# Consumer/gaming/commerce + social filler that is not AI×security news.
# Matched against items with no AI topic label; kept out of the hot ranking.
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
    "网警",
    "警方",
    "落网",
    "犯罪团伙",
    "犯罪嫌疑人",
    "倒卖",
    "黄牛",
    "演唱会",
    "门票",
    "代抢",
    "抓获",
)

HOT_TOP_N = 10
# Per-module cap for the timeline so a bulk module (cve) never starves the
# smaller modules (papers / trending) behind a single global limit.
PER_MODULE_MAX = 200
TIMEZONE_OFFSET_HOURS = 8  # Asia/Shanghai (no DST)

# Structured vulnerability feeds have their own score path and a disabled
# source (IT之家) is paused pending a filtering rule — neither belongs in the
# reading timeline.
EXCLUDED_ENDPOINTS = set(STRUCTURED_VULN_ENDPOINTS) | {"ithome-rss"}

# Module → endpoint mapping, same as the old daily report.
MODULES: list[dict] = [
    {
        "id": "news",
        "label": "资讯 · 新闻",
        "endpoints": [
            "aihot-selected-api",
            "aihot-selected-rss",
            "hackernews-api",
            "portswigger-research-rss",
            "google-security-rss",
            "trailofbits-rss",
            "wiz-blog-rss",
            "nvidia-blog-rss",
            "openai-news-rss",
            "google-blog-ai-rss",
            "anthropic-news",
            "apple-ml-research-rss",
            "huggingface-blog-rss",
        ],
    },
    {
        "id": "papers",
        "label": "论文 · 研究",
        "endpoints": ["arxiv-ai-llm", "arxiv-security-ai"],
    },
    {"id": "cve", "label": "CVE 漏洞", "endpoints": ["nvd-recent", "cisa-kev"]},
    {"id": "trending", "label": "开源 Trending", "endpoints": ["github-trending-rss"]},
]

_MODULE_BY_ENDPOINT = {ep: m["id"] for m in MODULES for ep in m["endpoints"]}


def _clean_summary(text: str | None, limit: int = 300) -> str:
    """Strip HTML tags and truncate to a sentence boundary."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", "", text).strip()
    if len(clean) <= limit:
        return clean
    snippet = clean[:limit]
    for sep in ("。", "！", "？", ". ", "! ", "? "):
        idx = snippet.rfind(sep)
        if idx > 50:
            return snippet[: idx + 1]
    return snippet.rstrip() + "…"


def _is_noise(title: str, topic: str | None) -> bool:
    """True for consumer/gaming/social filler without an AI topic label."""
    if topic:
        return False
    low = title.lower()
    return any(kw in low for kw in NOISE_KEYWORDS)


def _epoch_seconds(iso_value: str | None) -> float:
    if not iso_value:
        return 0.0
    try:
        return datetime.fromisoformat(iso_value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _shanghai_now() -> datetime:
    return datetime.now(UTC) + timedelta(hours=TIMEZONE_OFFSET_HOURS)


def _day_start_shanghai(day: date) -> datetime:
    naive = datetime.combine(day, datetime.min.time())
    return naive - timedelta(hours=TIMEZONE_OFFSET_HOURS)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def build_overview(
    session: Session,
    *,
    hot_top_n: int = HOT_TOP_N,
    per_module_max: int = PER_MODULE_MAX,
    natural_date: date | None = None,
) -> dict[str, Any]:
    """Return the frontend overview payload (hotspots + module timelines).

    Everything the public page needs in one call. Hotspots come from the frozen
    daily snapshot; timelines read the day's freshly-fetched documents live.
    ``natural_date`` defaults to today; pass an explicit date for the daily
    archive history view.
    """
    today = natural_date or _shanghai_now().date()
    day_start_utc = _day_start_shanghai(today)
    day_end_utc = _day_start_shanghai(today + timedelta(days=1))

    # --- today's hotspot snapshot (general category) ---
    snapshot = session.execute(
        select(DailyHotspotSnapshot)
        .where(
            DailyHotspotSnapshot.natural_date == today,
            DailyHotspotSnapshot.category == "general",
        )
        .order_by(desc(DailyHotspotSnapshot.revision))
        .limit(1)
    ).scalar_one_or_none()

    hotspots: list[dict] = []
    if snapshot is not None:
        seen_event_ids: set[int] = set()
        items = session.execute(
            select(DailyHotspotItem)
            .where(DailyHotspotItem.snapshot_id == snapshot.id)
            .order_by(DailyHotspotItem.rank)
        ).scalars()
        for item in items:
            payload = dict(item.payload)
            event_id = int(payload.get("id") or 0)
            if not event_id or event_id in seen_event_ids:
                continue
            if payload.get("category") == "vuln_db" or payload.get("topic") == "cve":
                continue  # CVE/vuln-db has its own score path — never mix with news
            seen_event_ids.add(event_id)
            title = payload.get("title") or ""
            topic = payload.get("topic")
            if _is_noise(title, topic):
                continue
            hotspots.append(
                {
                    "id": event_id,
                    "title": title,
                    "summary": _clean_summary(payload.get("summary"), 300),
                    "topic": topic,
                    "score": payload.get("score") or 0,
                    "source_count": int(payload.get("source_count") or 0),
                    "last": payload.get("last_seen_at"),
                }
            )
        hotspots.sort(
            key=lambda e: (
                -(e["source_count"]),
                -(e["score"] or 0),
                -_epoch_seconds(e["last"]),
            )
        )
        hotspots = hotspots[:hot_top_n]

    # --- today's timeline grouped by module ---
    source_labels_rows = session.execute(
        select(SourceEndpoint.id, Source.name)
        .join(Source, Source.id == SourceEndpoint.source_id)
    ).all()
    source_name = {row.id: row.name for row in source_labels_rows}

    module_endpoints = {ep for m in MODULES for ep in m["endpoints"]}
    rows = session.execute(
        select(
            Document.id,
            Document.title_original,
            Document.body_text,
            Document.canonical_url,
            Document.endpoint_id,
            Document.tech_directions,
            Document.classified_event_type,
            Document.entities,
            RawItem.fetched_at,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(
            Document.source_status == "active",
            Document.record_status == "published",
            Document.endpoint_id.in_(module_endpoints),
            RawItem.fetched_at >= day_start_utc,
            RawItem.fetched_at < day_end_utc,
        )
        .order_by(desc(RawItem.fetched_at))
    ).all()

    timeline_by_module: dict[str, list[dict]] = {}
    for doc_id, title_original, body_text, url, ep, tech, etype, entities, fetched_at in rows:
        topic = (tech or [None])[0] if tech else None
        if _is_noise(title_original, topic):
            continue
        module = _MODULE_BY_ENDPOINT.get(ep, "news")
        if module == "cve" and not is_followed_cve(entities or {}, title_original, body_text or ""):
            continue  # CVE follow policy: high CVSS AND followed software only
        bucket = timeline_by_module.setdefault(module, [])
        if len(bucket) >= per_module_max:
            continue
        bucket.append(
            {
                "document_id": doc_id,
                "title": title_original,
                "summary": _clean_summary(body_text, 300),
                "url": url,
                "source": ep,
                "source_name": source_name.get(ep, ep),
                "tech": tech or [],
                "etype": etype,
                "fetched": _iso(fetched_at),
            }
        )

    # --- "另有 N 家信源报道" mapping (canonical URL → endpoints) ---
    dup_rows = session.execute(
        select(Document.endpoint_id, Document.canonical_url)
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(
            Document.source_status == "active",
            Document.record_status == "published",
            Document.endpoint_id.in_(module_endpoints),
            RawItem.fetched_at >= day_start_utc,
            RawItem.fetched_at < day_end_utc,
        )
    ).all()
    url_sources: dict[str, list[str]] = {}
    for ep, url in dup_rows:
        url_sources.setdefault(str(url), []).append(str(ep))

    modules = [
        {
            "id": m["id"],
            "label": m["label"],
            "items": timeline_by_module.get(m["id"], []),
        }
        for m in MODULES
        if timeline_by_module.get(m["id"])
    ]

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "date": today.isoformat(),
        "weekday": ["周一", "周二", "周三", "周四", "周五", "周六", "周日"][today.weekday()],
        "hotspots": hotspots,
        "modules": modules,
        "url_sources": url_sources,
        "labels": {
            "source": SOURCE_LABELS,
            "tech": {
                "llm": "大模型",
                "ai_for_security": "AI for Security",
                "security_for_ai": "Security for AI",
                "agent": "智能体",
                "system_security": "系统安全",
            },
        },
    }


def module_names() -> Sequence[str]:
    """Stable module ids in render order."""
    return tuple(m["id"] for m in MODULES)
