"""Generate a self-contained HTML report of current classification data.

Reads documents from the DB, embeds them as JSON into a single HTML file with
inline CSS/JS (no external deps, no network). Re-runnable any time.

    uv run python scripts/gen_report.py [out.html]
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document

TECH_LABELS = {
    "ai_for_security": "AI for Security",
    "security_for_ai": "Security for AI",
    "agent": "Agent",
    "system_security": "系统安全",
}


def collect() -> tuple[list[dict], dict]:
    with session_scope() as session:
        rows = session.execute(select(Document).order_by(Document.id.desc())).scalars().all()
        docs = []
        tech_c: Counter = Counter()
        etype_c: Counter = Counter()
        company_c: Counter = Counter()
        source_c: Counter = Counter()
        for d in rows:
            td = d.tech_directions or []
            cm = d.company_models or []
            docs.append(
                {
                    "id": d.id,
                    "title": d.title_original,
                    "url": d.canonical_url,
                    "source": d.endpoint_id,
                    "lang": d.language,
                    "published": d.published_at_utc.isoformat() if d.published_at_utc else None,
                    "tech": td,
                    "company": cm,
                    "etype": d.classified_event_type,
                    "method": d.classify_method,
                    "conf": d.classify_confidence,
                    "cve": (d.identifiers or {}).get("cve", []),
                }
            )
            for t in td:
                tech_c[t] += 1
            for c in cm:
                company_c[c] += 1
            if d.classified_event_type:
                etype_c[d.classified_event_type] += 1
            source_c[d.endpoint_id] += 1
        stats = {
            "total": len(docs),
            "tech": dict(tech_c.most_common()),
            "etype": dict(etype_c.most_common()),
            "company": dict(company_c.most_common()),
            "source": dict(source_c.most_common()),
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        }
        return docs, stats


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("report.html")
    docs, stats = collect()
    payload = json.dumps(
        {"docs": docs, "stats": stats, "techLabels": TECH_LABELS}, ensure_ascii=False
    )
    template = (Path(__file__).parent / "report_template.html").read_text(encoding="utf-8")
    html = template.replace("/*__DATA__*/", payload)
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} — {stats['total']} documents, {out.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
