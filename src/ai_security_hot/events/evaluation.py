"""Offline, reproducible quality evaluation for M2 dedupe and clustering."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_security_hot.events.intelligence import (
    IntelDocument,
    build_event_drafts,
    deduplicate_documents,
)


@dataclass(frozen=True, slots=True)
class BinaryMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    wrong_merge_rate: float


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _binary_metrics(expected: list[bool], predicted: list[bool]) -> BinaryMetrics:
    tp = sum(want and got for want, got in zip(expected, predicted, strict=True))
    fp = sum(not want and got for want, got in zip(expected, predicted, strict=True))
    fn = sum(want and not got for want, got in zip(expected, predicted, strict=True))
    tn = sum(not want and not got for want, got in zip(expected, predicted, strict=True))
    return BinaryMetrics(
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=tn,
        precision=_ratio(tp, tp + fp),
        recall=_ratio(tp, tp + fn),
        wrong_merge_rate=_ratio(fp, tp + fp),
    )


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def document_from_label(data: dict[str, Any], *, fallback_id: int) -> IntelDocument:
    return IntelDocument(
        id=int(data.get("id", fallback_id)),
        endpoint_id=str(data.get("endpoint_id", f"eval-endpoint-{fallback_id}")),
        source_id=str(data.get("source_id", f"eval-source-{fallback_id}")),
        trust_tier=str(data.get("trust_tier", "B")),
        title=str(data["title"]),
        body=data.get("body"),
        canonical_url=str(data.get("url", f"https://eval.invalid/{fallback_id}")),
        published_at=_parse_time(data.get("published_at")),
        fetched_at=_parse_time(data.get("fetched_at")) or datetime(2026, 1, 1, tzinfo=UTC),
        identifiers=dict(data.get("identifiers") or {}),
        tech_directions=list(data.get("tech_directions") or []),
        event_type=data.get("event_type"),
        parse_quality=float(data.get("parse_quality", 0.8)),
        entities=dict(data.get("entities") or {}),
        company_models=list(data.get("company_models") or []),
    )


def load_quality_dataset(path: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        record = json.loads(stripped)
        if "case_id" not in record or "task" not in record:
            raise ValueError(f"invalid evaluation record at line {line_number}")
        records.append(record)
    return records


def _pair_prediction(record: dict[str, Any], *, cluster: bool) -> bool:
    left = document_from_label(record["left"], fallback_id=1)
    right = document_from_label(record["right"], fallback_id=2)
    if left.id == right.id:
        right = document_from_label({**record["right"], "id": left.id + 1}, fallback_id=2)
    documents = [left, right]
    decisions = deduplicate_documents(documents)
    if not cluster:
        left_master = decisions[left.id].near_dup_of or left.id
        right_master = decisions[right.id].near_dup_of or right.id
        return left_master == right_master
    drafts = build_event_drafts(documents, decisions)
    return any(
        {membership.document_id for membership in draft.memberships} >= {left.id, right.id}
        for draft in drafts.values()
    )


def evaluate_records(
    records: list[dict[str, Any]],
    *,
    top_n: int = 10,
    review_status: str | None = None,
) -> dict[str, Any]:
    review_counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("review_status", "unreviewed"))
        review_counts[status] = review_counts.get(status, 0) + 1
    selected = (
        records
        if review_status is None
        else [
            record
            for record in records
            if str(record.get("review_status", "unreviewed")) == review_status
        ]
    )
    dedupe_expected: list[bool] = []
    dedupe_predicted: list[bool] = []
    cluster_expected: list[bool] = []
    cluster_predicted: list[bool] = []
    ranking: list[dict[str, Any]] = []
    for record in selected:
        task = record["task"]
        if task == "dedupe_pair":
            dedupe_expected.append(bool(record["should_merge"]))
            dedupe_predicted.append(_pair_prediction(record, cluster=False))
        elif task == "cluster_pair":
            cluster_expected.append(bool(record["same_event"]))
            cluster_predicted.append(_pair_prediction(record, cluster=True))
        elif task == "ranking_event":
            ranking.append(record)
        else:
            raise ValueError(f"unknown evaluation task: {task}")

    ranked = sorted(ranking, key=lambda row: (-int(row.get("score", 0)), row["case_id"]))
    top = ranked[:top_n]
    relevant = [row for row in ranking if row.get("relevant")]
    first_party_relevant = [row for row in relevant if row.get("first_party")]
    return {
        "dataset_cases_total": len(records),
        "dataset_cases": len(selected),
        "metrics_scope": review_status or "all",
        "labels_reviewed_only": bool(selected)
        and all(str(row.get("review_status", "unreviewed")) == "reviewed" for row in selected),
        "review_status": review_counts,
        "dedupe": asdict(_binary_metrics(dedupe_expected, dedupe_predicted)),
        "cluster": asdict(_binary_metrics(cluster_expected, cluster_predicted)),
        "top_n": top_n,
        "top_n_relevance": _ratio(sum(bool(row.get("relevant")) for row in top), len(top)),
        "first_party_coverage": _ratio(len(first_party_relevant), len(relevant)),
        "ranking_cases": len(ranking),
    }


def evaluate_dataset(
    path: str | Path,
    *,
    top_n: int = 10,
    review_status: str | None = None,
) -> dict[str, Any]:
    return evaluate_records(
        load_quality_dataset(path),
        top_n=top_n,
        review_status=review_status,
    )
