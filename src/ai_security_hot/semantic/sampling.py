"""Stratified sampling for the shadow semantic-evaluation corpus.

Draws a reproducible stratified sample of current, non-CVE, duplicate-master
documents. Stratification keys are available on ``Document`` (source_id via the
endpoint join, tech_directions, classified_event_type, published_at bucket);
``content_type`` only exists on enrichment output, so it can only be aggregated
post-hoc, never used to draw the pre-enrichment sample.
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select

from ai_security_hot.domain.enums import STRUCTURED_VULN_ENDPOINTS
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, SourceEndpoint
from ai_security_hot.storage.repositories import current_document_conditions

# Cross-entity keys we stratify on. Source uses endpoint_id (available directly
# on Document); we do NOT need the SourceEndpoint join for the sample set.
STRATIFY_KEYS = ("source", "tech_direction", "event_type", "time_bucket")


def _time_bucket(published_at: datetime | None) -> str:
    """Bucket published time coarsely so recent/older docs share strata."""
    if published_at is None:
        return "unknown"
    year = published_at.year
    month = published_at.month
    if year >= 2026:
        return f"{year}-{month:02d}"
    return "pre-2026"


def _eligible_docs(session, exclude_vuln: bool = True) -> list[Document]:
    """Current, published, classified, non-CVE, deduped duplicate-master docs."""
    conditions = list(current_document_conditions())
    conditions += [
        Document.classified_at.is_not(None),
        Document.tech_directions != ["cve"],
        Document.dedupe_version.is_not(None),
        Document.near_dup_of.is_(None),
    ]
    if exclude_vuln:
        conditions.append(Document.endpoint_id.notin_(STRUCTURED_VULN_ENDPOINTS))
    return list(session.execute(select(Document).where(*conditions)).scalars())


def _doc_stratum(doc: Document) -> dict[str, str]:
    return {
        "source": doc.endpoint_id,
        "tech_direction": (doc.tech_directions or ["none"])[0],
        "event_type": doc.classified_event_type or "none",
        "time_bucket": _time_bucket(doc.published_at_utc),
    }


def stratified_sample(session, *, size: int, seed: int = 20260801) -> list[Document]:
    """Source-balanced round-robin draw, deterministic (reproducible).

    Stratifies by source first so no single source dominates (the known skew:
    96/110 enrichments came from ithome). Then within each source a
    deterministic shuffle makes the draw reproducible.
    """
    docs = _eligible_docs(session)
    if not docs:
        return []

    by_source: dict[str, list[Document]] = defaultdict(list)
    for doc in docs:
        by_source[doc.endpoint_id].append(doc)

    # Seeded PRNG is intentional: sampling must be reproducible, not secure.
    rng = random.Random(seed)  # noqa: S311
    for source_docs in by_source.values():
        rng.shuffle(source_docs)

    selected: list[Document] = []
    source_order = sorted(by_source)  # deterministic order
    while len(selected) < size:
        before = len(selected)
        for source in source_order:
            source_docs = by_source[source]
            if source_docs and len(selected) < size:
                selected.append(source_docs.pop())
        if len(selected) == before:  # every source exhausted
            break
    return selected[:size]


def write_manifest(
    docs: list[Document],
    *,
    batch_id: str,
    out_path: Path,
) -> dict:
    """Write a reproducible JSONL manifest of the sampled documents."""
    records = []
    for doc in docs:
        stratum = _doc_stratum(doc)
        records.append(
            {
                "case_id": f"{batch_id}:{doc.id}",
                "batch_id": batch_id,
                "document_id": doc.id,
                "source": doc.endpoint_id,
                "title": doc.title_original,
                "url": doc.canonical_url,
                "published_at": (
                    doc.published_at_utc.isoformat() if doc.published_at_utc else None
                ),
                "tech_directions": doc.tech_directions or [],
                "event_type": doc.classified_event_type,
                "stratum": stratum,
            }
        )
    out_path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )
    by_source = Counter(stratum["source"] for stratum in (r["stratum"] for r in records))
    return {
        "batch_id": batch_id,
        "sampled": len(records),
        "manifest": str(out_path),
        "by_source": dict(by_source.most_common()),
        "seed": 20260801,
    }


def load_manifest(path: str | Path) -> list[int]:
    """Load document ids from a previously written manifest."""
    ids = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        record = json.loads(line)
        if record.get("document_id") is not None:
            ids.append(int(record["document_id"]))
    return ids


def run_sampling(*, size: int, batch_id: str, manifest: str | None = None) -> dict:
    """Sample, write manifest, and return the manifest summary."""
    with session_scope() as session:
        docs = stratified_sample(session, size=size)
        if manifest:
            out = Path(manifest)
        else:
            out = Path(f"evaluation/{batch_id}.jsonl")
        return write_manifest(docs, batch_id=batch_id, out_path=out)


def source_stats() -> dict:
    """Report the eligible-corpus source distribution (pre-sampling overview)."""
    with session_scope() as session:
        rows = session.execute(
            select(SourceEndpoint.id, func.count())
            .join(Document, Document.endpoint_id == SourceEndpoint.id)
            .group_by(SourceEndpoint.id)
            .order_by(func.count().desc())
        ).all()
    return {str(endpoint_id): int(count) for endpoint_id, count in rows}
