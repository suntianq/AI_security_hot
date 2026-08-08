"""Offline aggregation for a fixed semantic-evaluation batch (M2.2.2).

Reads DocumentEnrichment + SemanticWorkItem rows for one ``batch_id`` and
reports proxy metrics: relevance ratio (broken down by source / tech direction /
content type), evidence exact-hit rate, structural failure rate, cost and
latency. This is a proxy report, not human-gold precision/recall — that label
is reserved for reviewed annotation assets under ``evaluation/``.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.semantic_tables import (
    DocumentEnrichment,
    EntityMention,
    ExtractedClaim,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import Document

CONTENT_TYPE_LABELS = {
    "news": "新闻",
    "research": "研究",
    "release": "发布",
    "advisory": "公告",
    "incident": "事故",
    "opinion": "观点",
    "other": "其他",
}
TECH_LABELS = {
    "cve": "CVE 漏洞",
    "llm": "大模型",
    "ai_for_security": "AI for Security",
    "security_for_ai": "Security for AI",
    "agent": "智能体",
    "system_security": "系统安全",
}


def _split_by(
    documents: dict[int, Document],
    enrichments: list[DocumentEnrichment],
    key: str,
) -> dict:
    """Group enrichments by a document-level attribute for breakdown reporting."""
    groups: dict[str, Counter] = defaultdict(Counter)
    for enr in enrichments:
        doc = documents.get(enr.document_id)
        value = "unknown"
        if doc is not None:
            if key == "source":
                value = doc.endpoint_id
            elif key == "tech_direction":
                value = (doc.tech_directions or ["none"])[0]
            elif key == "content_type":
                value = enr.content_type
        groups[value]["total"] += 1
        groups[value]["relevant"] += int(enr.relevant)
    return {
        str(value): {
            "total": int(c["total"]),
            "relevant": int(c["relevant"]),
            "ratio": round(c["relevant"] / c["total"], 3) if c["total"] else 0.0,
        }
        for value, c in sorted(groups.items())
    }


def _evidence_metrics(session, batch_id: str) -> dict:
    """Evidence exact-hit rate across entity mentions and claims for the batch."""
    enrichment_ids = list(
        session.execute(
            select(DocumentEnrichment.id).where(DocumentEnrichment.batch_id == batch_id)
        ).scalars()
    )
    if not enrichment_ids:
        return {"mentions": 0, "claims": 0, "exact": 0.0}
    return _evidence_metrics_for(session, enrichment_ids)


def _usage_stats(enrichments: list[DocumentEnrichment]) -> dict:
    totals: dict[str, int] = Counter()
    for enr in enrichments:
        usage = enr.usage or {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            totals[key] += int(usage.get(key) or 0)
    return {key: int(totals[key]) for key in ("prompt_tokens", "completion_tokens", "total_tokens")}


def evaluate_batch(batch_id: str, *, manifest: str | None = None) -> dict:
    """Aggregate proxy metrics for one semantic batch."""
    with session_scope() as session:
        enrichments = list(
            session.execute(
                select(DocumentEnrichment).where(DocumentEnrichment.batch_id == batch_id)
            ).scalars()
        )
        work_rows = list(
            session.execute(
                select(SemanticWorkItem).where(SemanticWorkItem.batch_id == batch_id)
            ).scalars()
        )
        document_ids = {enr.document_id for enr in enrichments}
        doc_rows = session.execute(
            select(Document).where(Document.id.in_(document_ids))
        ).scalars()
        documents = {doc.id: doc for doc in doc_rows}

        work_status = Counter(row.status for row in work_rows)
        total_work = len(work_rows) or 1
        failed_structural = work_status.get("failed", 0) + work_status.get("retry", 0)
        # Latency is not persisted per-run start today; report it as unknown
        # rather than fabricating zeros. Recording real latency is a follow-up.
        p50 = p95 = None

        usage = _usage_stats(enrichments)

        result = {
            "batch_id": batch_id,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "enrichments": len(enrichments),
            "work_items": len(work_rows),
            "work_status": dict(work_status),
            "structural_failure_rate": round(failed_structural / total_work, 3),
            "relevance": {
                "total": len(enrichments),
                "relevant": sum(1 for e in enrichments if e.relevant),
                "ratio": round(
                    sum(1 for e in enrichments if e.relevant) / max(len(enrichments), 1), 3
                ),
            },
            "by_source": _split_by(documents, enrichments, "source"),
            "by_tech_direction": _split_by(documents, enrichments, "tech_direction"),
            "by_content_type": _split_by(documents, enrichments, "content_type"),
            "evidence": _evidence_metrics(session, batch_id),
            "cost": {
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
                "total_tokens": usage["total_tokens"],
            },
            "latency_ms": {"p50": p50, "p95": p95},
            "labels": {
                "content_type": CONTENT_TYPE_LABELS,
                "tech_direction": TECH_LABELS,
            },
        }
        if manifest:
            result["manifest"] = str(manifest)
            lines = Path(manifest).read_text(encoding="utf-8").splitlines()
            result["manifest_size"] = len([line for line in lines if line.strip()])
        return result


def _evidence_metrics_for(session, enrichment_ids: list[int]) -> dict:
    from ai_security_hot.models.semantic_tables import AtomicEvent

    mention_rows = session.execute(
        select(EntityMention.evidence_field).where(
            EntityMention.enrichment_id.in_(enrichment_ids)
        )
    ).scalars().all()
    claim_rows = session.execute(
        select(ExtractedClaim.evidence_field)
        .join(AtomicEvent, ExtractedClaim.atomic_event_id == AtomicEvent.id)
        .where(AtomicEvent.enrichment_id.in_(enrichment_ids))
    ).scalars().all()
    exact_mentions = sum(1 for f in mention_rows if f != "unknown")
    exact_claims = sum(1 for f in claim_rows if f != "unknown")
    total = len(mention_rows) + len(claim_rows)
    return {
        "mentions": len(mention_rows),
        "claims": len(claim_rows),
        "exact": round((exact_mentions + exact_claims) / total, 3) if total else 0.0,
    }
