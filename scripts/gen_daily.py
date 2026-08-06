"""Generate a daily HTML report in the aihot-style layout.

Reads today's freshly-fetched documents + hotspots from PostgreSQL and renders
a single self-contained HTML page:

  - 今日热点 Top 5-10: today's window, multi-source first, general news only
    (CVE / vuln-db entries are deliberately excluded — they have their own
    score path and must not mix with the news ranking).
  - 按日时间线: today's news cards with fetch time, source, title (links to
    the original), summary, and a "另有 N 家信源报道" marker.

The report is only generated after the daily snapshot exists, so it never runs
before the day's sources have been fetched.

    uv run python scripts/gen_daily.py [out.html]

Output defaults to ./delivery/daily-YYYY-MM-DD.html.
"""

from __future__ import annotations

import re
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select

from ai_security_hot.domain.enums import STRUCTURED_VULN_ENDPOINTS
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import (
    DailyHotspotItem,
    DailyHotspotSnapshot,
    Document,
    RawItem,
    Source,
    SourceEndpoint,
)
from ai_security_hot.reporting import json_for_html_script

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
    "ithome-rss": "IT之家",
    "google-blog-ai-rss": "Google Blog AI",
    "github-trending-rss": "GitHub Trending",
}

# Consumer/gaming/commerce filler that is not AI×security news. Matched against
# single-source items with no topic label; kept out of the hot ranking.
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
# Per-module cap for the timeline. Each module scrolls independently, so a
# generous cap keeps every section populated without a single global limit
# starving the smaller modules (papers/trending) behind bulk CVE/blackhat rows.
PER_MODULE_MAX = 200
TIMEZONE_OFFSET_HOURS = 8  # Asia/Shanghai

# Endpoints excluded from the reading timeline: structured vulnerability feeds
# (they have their own score path) plus disabled sources such as IT之家 that
# are paused pending a filtering rule.
EXCLUDED_ENDPOINTS = set(STRUCTURED_VULN_ENDPOINTS) | {"ithome-rss"}

# Daily-report modules: which endpoint groups appear under which section.
# Each module has a label and the endpoints that feed it. Documents not in any
# module fall into "news" by default.
MODULES = [
    {"id": "news", "label": "资讯 · 新闻", "endpoints": [
        "aihot-selected-api", "aihot-selected-rss", "hackernews-rss",
        "portswigger-research-rss", "google-security-rss", "trailofbits-rss",
        "wiz-blog-rss", "nvidia-blog-rss", "openai-news-rss",
        "google-blog-ai-rss", "anthropic-news", "apple-ml-research-rss",
        "huggingface-blog-rss",
    ]},
    {"id": "papers", "label": "论文 · 研究", "endpoints": [
        "arxiv-ai-llm", "arxiv-security-ai",
    ]},
    {"id": "cve", "label": "CVE 漏洞", "endpoints": ["nvd-recent", "cisa-kev"]},
    {"id": "trending", "label": "开源 Trending", "endpoints": ["github-trending-rss"]},
    {"id": "blackhat", "label": "Black Hat", "endpoints": ["blackhat-us26-briefings"]},
]

_MODULE_BY_ENDPOINT = {
    ep: m["id"] for m in MODULES for ep in m["endpoints"]
}



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
    """True for single-source consumer/gaming filler without an AI topic."""
    if topic:
        return False  # classified into an AI×security topic
    low = title.lower()
    return any(kw in low for kw in NOISE_KEYWORDS)


def _epoch_seconds(iso_value: str | None) -> float:
    """Parse an ISO timestamp to epoch seconds for sorting; 0 when absent."""
    if not iso_value:
        return 0.0
    try:
        return datetime.fromisoformat(iso_value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _shanghai_now() -> datetime:
    """Current time in Asia/Shanghai (UTC+8, no DST)."""
    return datetime.now(UTC) + timedelta(hours=TIMEZONE_OFFSET_HOURS)


def _day_start_shanghai(day: date) -> datetime:
    """Midnight of the given natural day in Asia/Shanghai, as UTC."""
    naive = datetime.combine(day, datetime.min.time())
    return naive - timedelta(hours=TIMEZONE_OFFSET_HOURS)


def collect(session) -> dict[str, Any]:
    """Collect today's hotspots + timeline data."""
    today = _shanghai_now().date()
    day_start_utc = _day_start_shanghai(today)
    day_end_utc = _day_start_shanghai(today + timedelta(days=1))

    # --- today's hotspot snapshot (must exist before generating) ---
    # The "general" category snapshot holds the reading hotspot ranking only —
    # NVD/KEV CVE entries live in their own "vuln_db" snapshot and are never
    # mixed into the news ranking.
    snapshot = session.execute(
        select(DailyHotspotSnapshot)
        .where(
            DailyHotspotSnapshot.natural_date == today,
            DailyHotspotSnapshot.category == "general",
        )
        .order_by(desc(DailyHotspotSnapshot.revision))
        .limit(1)
    ).scalar_one_or_none()
    if snapshot is None:
        raise RuntimeError(
            f"no daily hotspot snapshot for {today.isoformat()} yet — "
            "run `intel daily-snapshot` (or wait for the worker) before generating"
        )
    snapshot_generated_at = snapshot.generated_at

    # --- hot ranking from the snapshot: today window, general only, multi-source first ---
    items = session.execute(
        select(DailyHotspotItem)
        .where(DailyHotspotItem.snapshot_id == snapshot.id)
        .order_by(DailyHotspotItem.rank)
    ).scalars()
    hotspots: list[dict] = []
    seen_event_ids: set[int] = set()
    for item in items:
        payload = dict(item.payload)
        event_id = int(payload.get("id") or 0)
        if not event_id or event_id in seen_event_ids:
            continue
        # CVE / vuln-db entries have their own score path — never mix with news.
        category = payload.get("category")
        topic = payload.get("topic")
        if category == "vuln_db" or topic == "cve":
            continue
        seen_event_ids.add(event_id)
        title = payload.get("title") or ""
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
                "_sort_ts": _epoch_seconds(payload.get("last_seen_at")),
            }
        )
    # Multi-source first, then score, then recency.
    hotspots.sort(
        key=lambda e: (
            -(e["source_count"]),
            -(e["score"] or 0),
            -e["_sort_ts"],
        )
    )
    hotspots = hotspots[: HOT_TOP_N]

    # --- today's timeline grouped by module ---
    source_labels_rows = session.execute(
        select(SourceEndpoint.id, Source.name)
        .join(Source, Source.id == SourceEndpoint.source_id)
    ).all()
    source_name = {row.id: row.name for row in source_labels_rows}

    # All module endpoints combined (CVE included; it has its own section).
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
            Document.published_at_utc,
            RawItem.fetched_at,
            Document.identifiers,
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
    for row in rows:
        title = row.title_original
        topic = (row.tech_directions or ["?"])[0] if row.tech_directions else None
        if _is_noise(title, topic):
            continue
        module = _MODULE_BY_ENDPOINT.get(row.endpoint_id, "news")
        bucket = timeline_by_module.setdefault(module, [])
        if len(bucket) >= PER_MODULE_MAX:
            continue  # module already full — keep the newest PER_MODULE_MAX rows
        bucket.append(
            {
                "title": title,
                "summary": _clean_summary(row.body_text, 300),
                "url": row.canonical_url,
                "source": row.endpoint_id,
                "source_name": source_name.get(row.endpoint_id, row.endpoint_id),
                "tech": row.tech_directions or [],
                "etype": row.classified_event_type,
                "fetched": row.fetched_at.isoformat() if row.fetched_at else None,
                "pub": row.published_at_utc.isoformat() if row.published_at_utc else None,
            }
        )

    # --- source counts per endpoint (for the "另有 N 家信源报道" marker) ---
    dup_rows = session.execute(
        select(Document.endpoint_id, Document.canonical_url, func.count())
        .where(
            Document.source_status == "active",
            Document.record_status == "published",
            Document.endpoint_id.in_(module_endpoints),
            RawItem.fetched_at >= day_start_utc,
            RawItem.fetched_at < day_end_utc,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .group_by(Document.endpoint_id, Document.canonical_url)
    ).all()
    url_sources: dict[str, list[str]] = {}
    for endpoint, url, _count in dup_rows:
        url_sources.setdefault(str(url), []).append(str(endpoint))

    # Ordered modules: only modules with content are emitted; others omitted.
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
        "snapshot_generated_at": snapshot_generated_at.isoformat(),
        "hotspots": hotspots,
        "modules": modules,
        "url_sources": url_sources,
        "labels": {
            "source": SOURCE_LABELS,
            "tech": {
                "llm": "大模型",
                "ai_for_security": "AI 用于安全",
                "security_for_ai": "AI 自身安全",
                "agent": "智能体",
                "system_security": "系统安全",
            },
        },
    }


_TEMPLATE = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI × Security 日报 · {date}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg0:#0f172a;--bg1:#1e293b;--card:rgba(255,255,255,.06);--card-solid:#1e293b;
  --line:rgba(255,255,255,.1);--hover:rgba(255,255,255,.12);
  --fg:#e2e8f0;--mut:#94a3b8;--dim:#64748b;
  --acc:#38bdf8;--acc2:#818cf8;--acc3:#34d399;
  --c1:#f87171;--c2:#fbbf24;--c3:#34d399;--c4:#a78bfa;--c5:#22d3ee;--c6:#fb923c;
  --radius:14px;--shadow:0 8px 30px rgba(0,0,0,.35);
}}
body{{
  background:radial-gradient(1200px 800px at 80% -10%,rgba(56,189,248,.15),transparent 60%),
             radial-gradient(1000px 600px at -10% 20%,rgba(129,140,248,.12),transparent 55%),
             linear-gradient(160deg,var(--bg0),var(--bg1));
  background-attachment:fixed;min-height:100vh;color:var(--fg);
  font:15px/1.65 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
}}
a{{color:inherit;text-decoration:none}}
::selection{{background:rgba(56,189,248,.3)}}

/* Header */
header{{
  position:sticky;top:0;z-index:100;
  background:rgba(15,23,42,.75);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--line);
}}
.header-inner{{max-width:920px;margin:0 auto;padding:14px 24px;display:flex;
  align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}}
.brand{{display:flex;align-items:center;gap:12px}}
.logo{{width:38px;height:38px;border-radius:11px;flex-shrink:0;
  background:linear-gradient(135deg,var(--acc),var(--acc2));
  display:flex;align-items:center;justify-content:center;
  font-weight:800;font-size:17px;color:#0f172a;box-shadow:0 4px 14px rgba(56,189,248,.4)}}
.brand h1{{font-size:18px;font-weight:700;letter-spacing:.3px;
  background:linear-gradient(90deg,#e2e8f0,#94a3b8);-webkit-background-clip:text;
  -webkit-text-fill-color:transparent}}
.brand h1 span{{font-size:13px;font-weight:500;color:var(--dim);
  -webkit-text-fill-color:var(--dim);margin-left:8px}}
.meta-chip{{display:flex;gap:8px;align-items:center}}
.chip{{font-size:12px;padding:5px 12px;border-radius:20px;border:1px solid var(--line);
  background:var(--card);color:var(--mut);backdrop-filter:blur(6px)}}
.chip.accent{{border-color:rgba(56,189,248,.4);color:var(--acc);
  background:rgba(56,189,248,.08)}}

.wrap{{max-width:920px;margin:0 auto;padding:28px 24px 40px}}

/* Section titles */
.hot-title{{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:700;
  margin:8px 0 16px;letter-spacing:.2px}}
.hot-title .bar{{width:4px;height:18px;border-radius:2px;
  background:linear-gradient(180deg,var(--acc),var(--acc2));box-shadow:0 0 10px rgba(56,189,248,.5)}}
.hot-title .count{{font-size:12px;color:var(--dim);font-weight:500;margin-left:auto}}

/* Hot ranking — glass cards */
.hot-list{{display:grid;gap:10px}}
.hot-item{{
  display:flex;align-items:flex-start;gap:14px;padding:16px 18px;
  background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  backdrop-filter:blur(8px);box-shadow:var(--shadow);
  transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease;
}}
.hot-item:hover{{transform:translateY(-2px);border-color:rgba(56,189,248,.4);
  box-shadow:0 12px 40px rgba(0,0,0,.45)}}
.hot-rank{{
  font-size:22px;font-weight:800;min-width:30px;text-align:center;line-height:1.3;
  background:linear-gradient(180deg,var(--dim),var(--mut));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  font-style:italic;letter-spacing:-1px;
}}
.hot-rank.r1{{background:linear-gradient(180deg,#fbbf24,#f87171);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hot-rank.r2{{background:linear-gradient(180deg,#e2e8f0,#94a3b8);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hot-rank.r3{{background:linear-gradient(180deg,#fdba74,#f97316);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hot-body{{flex:1;min-width:0}}
.hot-title-text{{font-weight:600;font-size:14.5px;margin-bottom:5px;color:#f1f5f9;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.hot-summary{{font-size:13px;color:var(--mut);line-height:1.55;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}}
.hot-meta{{display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap}}
.hot-score{{font-size:11.5px;font-weight:700;padding:3px 10px;border-radius:20px;
  background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;
  box-shadow:0 2px 8px rgba(249,115,22,.35)}}
.hot-score.s70{{background:linear-gradient(135deg,#ef4444,#f43f5e);
  box-shadow:0 2px 8px rgba(239,68,68,.35)}}
.src-badge{{font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;
  border:1px solid rgba(52,211,153,.4);color:var(--c3);background:rgba(52,211,153,.08)}}
.src-badge.multi{{border-color:rgba(56,189,248,.5);color:var(--acc);
  background:rgba(56,189,248,.1);box-shadow:0 0 10px rgba(56,189,248,.15)}}
.topic-tag{{font-size:11px;padding:3px 10px;border-radius:20px;border:1px solid var(--line);
  color:var(--mut);background:rgba(255,255,255,.05)}}

/* Timeline — left rail with dots */
.timeline-wrap{{position:relative;padding-left:26px}}
.timeline-wrap::before{{content:'';position:absolute;left:7px;top:4px;bottom:4px;
  width:2px;background:linear-gradient(180deg,rgba(56,189,248,.5),rgba(129,140,248,.15),transparent)}}
.tl-item{{
  position:relative;display:flex;gap:14px;padding:14px 16px;margin-bottom:8px;
  background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  backdrop-filter:blur(8px);transition:transform .15s ease,border-color .15s ease;
}}
.tl-item::before{{
  content:'';position:absolute;left:-24px;top:22px;width:10px;height:10px;
  border-radius:50%;background:var(--acc);border:2px solid var(--bg1);
  box-shadow:0 0 8px rgba(56,189,248,.6);
}}
.tl-item:hover{{transform:translateX(2px);border-color:rgba(56,189,248,.35)}}
.tl-time{{font-size:12.5px;color:var(--dim);min-width:44px;flex-shrink:0;
  font-variant-numeric:tabular-nums;padding-top:2px;letter-spacing:.5px}}
.tl-body{{flex:1;min-width:0}}
.tl-meta{{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}}
.tl-source{{font-size:12px;font-weight:600;color:var(--acc);letter-spacing:.2px}}
.tl-title{{font-size:14px;font-weight:600;line-height:1.45;margin-bottom:4px;color:#f1f5f9}}
.tl-title a{{transition:color .15s}}
.tl-title a:hover{{color:var(--acc)}}
.tl-summary{{font-size:13px;color:var(--mut);line-height:1.55;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}}
.tl-multi{{font-size:11.5px;color:var(--c3);margin-top:5px;display:inline-flex;
  align-items:center;gap:4px}}
.tl-multi::before{{content:'↗';font-weight:700}}
.tl-tags{{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}}
.tag{{font-size:10.5px;padding:2px 9px;border-radius:12px;border:1px solid}
.tag.llm{{color:var(--c5);border-color:rgba(34,211,238,.35);background:rgba(34,211,238,.08)}}
.tag.ai_for_security{{color:var(--c3);border-color:rgba(52,211,153,.35);background:rgba(52,211,153,.08)}}
.tag.security_for_ai{{color:var(--c2);border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.08)}}
.tag.agent{{color:var(--c4);border-color:rgba(167,139,250,.35);background:rgba(167,139,250,.08)}}
.tag.system_security{{color:var(--c6);border-color:rgba(251,146,60,.35);background:rgba(251,146,60,.08)}}
.tag.et{{color:var(--acc);border-color:rgba(56,189,248,.35);background:rgba(56,189,248,.08)}}

/* Collapsible module + scrollable body */
.hot-section[data-module] .hot-title{{cursor:pointer;user-select:none;
  transition:color .15s ease}}
.hot-section[data-module] .hot-title:hover{{color:var(--acc)}}
.hot-section[data-module] .hot-title .chevron{{margin-left:8px;font-size:12px;
  color:var(--dim);transition:transform .2s ease}}
.hot-section[data-module].collapsed .hot-title .chevron{{transform:rotate(-90deg)}}
.module-scroll{{
  max-height:460px;overflow-y:auto;overflow-x:hidden;
  padding:2px 10px 2px 2px;margin-right:-6px;
  transition:max-height .25s ease;
}}
.hot-section[data-module].collapsed .module-scroll{{max-height:0;overflow:hidden;
  padding-top:0;padding-bottom:0}}
.module-scroll::-webkit-scrollbar{{width:8px}}
.module-scroll::-webkit-scrollbar-track{{background:transparent}}
.module-scroll::-webkit-scrollbar-thumb{{background:rgba(148,163,184,.25);
  border-radius:8px;border:2px solid transparent;background-clip:padding-box}}
.module-scroll::-webkit-scrollbar-thumb:hover{{background:rgba(148,163,184,.45);
  background-clip:padding-box}}
.module-scroll{{scrollbar-width:thin;scrollbar-color:rgba(148,163,184,.3) transparent}}

footer{{text-align:center;padding:24px;color:var(--dim);font-size:12px;
  border-top:1px solid var(--line);margin-top:20px}}
footer .dot{{display:inline-block;width:6px;height:6px;border-radius:50%;
  background:var(--acc);margin-right:6px;animation:pulse 2.5s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}

@media(max-width:640px){{
  .hot-rank{{font-size:18px;min-width:24px}}
  .wrap{{padding:18px 14px}}
  .tl-item{{padding:12px 12px}}
  .chip{{display:none}}
}}
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <div class="brand">
      <div class="logo">AI</div>
      <h1>Security Hot 日报<span>{date_label}</span></h1>
    </div>
    <div class="meta-chip">
      <span class="chip accent">● 每日精选</span>
      <span class="chip">快照 {snapshot_at}</span>
    </div>
  </div>
</header>
<div class="wrap">
  <div class="hot-section">
    <div class="hot-title"><span class="bar"></span>今日热点 <span class="count">多来源优先 · 仅资讯</span></div>
    <div class="hot-list" id="hotList"></div>
  </div>
  <div id="modules"></div>
</div>
<footer><span class="dot"></span>生成于 {generated_at} · AI Security Hot</footer>

<script id="data" type="application/json">/*__DATA__*/</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const L = D.labels;
const $ = id => document.getElementById(id);
const esc = s => String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

// ---- Hot ranking ----
$('hotList').innerHTML = (D.hotspots||[]).map((e,i)=>{
  const sc = e.score ?? 0;
  const cls = sc>=70?'s70':'';
  const rankCls = `r${Math.min(i+1,3)}`;
  const srcBadge = (e.source_count||0)>=2
    ? `<span class="src-badge multi">${e.source_count} 源印证</span>`
    : `<span class="src-badge">${e.source_count||1} 源</span>`;
  return `<div class="hot-item">
    <div class="hot-rank ${rankCls}">${String(i+1).padStart(2,'0')}</div>
    <div class="hot-body">
      <div class="hot-title-text">${esc(e.title)}</div>
      ${e.summary?`<div class="hot-summary">${esc(e.summary)}</div>`:''}
      <div class="hot-meta">
        <span class="hot-score ${cls}">${sc} 热度</span>
        ${srcBadge}
        ${e.topic?`<span class="topic-tag">${esc(L.tech[e.topic]||e.topic)}</span>`:''}
      </div>
    </div>
  </div>`;
}).join('') || '<div style="color:var(--dim);padding:24px">今日暂无热点</div>';

// ---- Modules (each section is one content type) ----
function techTags(arr){
  return (arr||[]).filter(x=>x!=='cve').map(x=>`<span class="tag ${x}">${esc(L.tech[x]||x)}</span>`).join('');
}
function multiSources(url){
  const srcs = (D.url_sources||{})[url]||[];
  if(srcs.length<=1) return '';
  const names = srcs.map(s=>esc(L.source[s]||s)).join('、');
  return `<span class="tl-multi">另有 ${srcs.length-1} 家信源报道 · ${names}</span>`;
}
function moduleItem(d){
  return `<div class="tl-item">
    <div class="tl-time">${esc((d.fetched||'').substring(11,16))}</div>
    <div class="tl-body">
      <div class="tl-meta">
        <span class="tl-source">${esc(d.source_name||L.source[d.source]||d.source)}</span>
      </div>
      <div class="tl-title"><a href="${esc(d.url)}" target="_blank" rel="noopener">${esc(d.title)}</a></div>
      ${d.summary?`<div class="tl-summary">${esc(d.summary)}</div>`:''}
      ${multiSources(d.url)}
      ${d.tech&&d.tech.length?`<div class="tl-tags">${techTags(d.tech)}</div>`:''}
    </div>
  </div>`;
}
const moduleHTML = (D.modules||[]).map(m=>`
  <div class="hot-section" data-module="${esc(m.id)}">
    <div class="hot-title"><span class="bar"></span>${esc(m.label)}
      <span class="count">${m.items.length} 条</span><span class="chevron">▼</span></div>
    <div class="module-scroll">
      <div class="timeline-wrap">${m.items.map(moduleItem).join('')}</div>
    </div>
  </div>`).join('');
$('modules').innerHTML = moduleHTML || '<div style="color:var(--dim);padding:24px">今日暂无内容</div>';

// Click a module title to collapse/expand its scrollable body.
document.querySelectorAll('.hot-section[data-module] .hot-title').forEach(t=>{
  t.addEventListener('click', ()=> t.parentElement.classList.toggle('collapsed'));
});
</script>
</body>
</html>
"""


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("delivery")
    with session_scope() as session:
        data = collect(session)
    payload = json_for_html_script(data)
    today = data["date"]
    date_label = f"{int(today[5:7])}月{int(today[8:10])}日 · {data['weekday']}"
    html = (
        _TEMPLATE.replace("/*__DATA__*/", payload)
        .replace("{date}", today)
        .replace("{date_label}", date_label)
        .replace("{generated_at}", data["generated_at"][:16].replace("T", " "))
        .replace("{snapshot_at}", data["snapshot_generated_at"][:16].replace("T", " "))
    )
    # Un-escape the doubled braces used to keep the CSS template literal valid
    # while this module is Python. Only inside <style>, so JS ${...} is safe.
    html = re.sub(
        r"<style>.*?</style>",
        lambda m: m.group(0).replace("{{", "{").replace("}}", "}"),
        html,
        flags=re.S,
    )
    out.mkdir(parents=True, exist_ok=True)
    out = out / f"daily-{today}.html"
    out.write_text(html, encoding="utf-8")
    module_counts = {m["id"]: len(m["items"]) for m in data["modules"]}
    print(
        f"wrote {out} — {len(data['hotspots'])} hotspots, "
        f"modules={module_counts}, {out.stat().st_size // 1024} KB"
    )


if __name__ == "__main__":
    main()
