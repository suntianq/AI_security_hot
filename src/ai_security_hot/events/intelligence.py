"""Versioned, deterministic deduplication and event construction.

This module is deliberately pure: it makes no database or network calls. The
pipeline can therefore replay a rule version and explain every relationship.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from rapidfuzz import fuzz

DEDUPE_VERSION = "dedupe-v1"
CLUSTER_VERSION = "cluster-v1"
FUZZY_TITLE_THRESHOLD = 94.0

_ARXIV_RE = re.compile(r"arxiv\.org/(?:abs|pdf)/([0-9]{4}\.[0-9]{4,5})(?:v[0-9]+)?", re.I)
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9+.#_-]{2,}")
_SPACE_RE = re.compile(r"\s+")
_IDENTIFIER_PATTERNS = {
    "cve": re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}"),
    "ghsa": re.compile(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"),
    "cnvd": re.compile(r"CNVD-[0-9]{4}-[0-9]+"),
}


@dataclass(frozen=True, slots=True)
class IntelDocument:
    id: int
    endpoint_id: str
    source_id: str
    trust_tier: str
    title: str
    body: str | None
    canonical_url: str
    published_at: datetime | None
    fetched_at: datetime | None
    identifiers: dict[str, Any]
    tech_directions: list[str]
    event_type: str | None
    parse_quality: float


@dataclass(frozen=True, slots=True)
class DedupDecision:
    document_id: int
    near_dup_of: int | None
    duplicate_kind: str | None
    duplicate_score: float | None


@dataclass(frozen=True, slots=True)
class EventKey:
    fingerprint: str
    kind: str


@dataclass(frozen=True, slots=True)
class EventMembership:
    document_id: int
    evidence_level: str
    relation_reason: str


@dataclass(frozen=True, slots=True)
class EventDraft:
    fingerprint: str
    event_type: str | None
    topic: str | None
    title: str
    summary: str | None
    status: str
    score: int
    evidence_level: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    memberships: tuple[EventMembership, ...]


class _UnionFind:
    def __init__(self, ids: list[int]) -> None:
        self.parent = {document_id: document_id for document_id in ids}

    def find(self, document_id: int) -> int:
        parent = self.parent[document_id]
        if parent != document_id:
            self.parent[document_id] = self.find(parent)
        return self.parent[document_id]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def normalize_title(value: str) -> str:
    """Normalize case, width, punctuation and whitespace without translating."""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    chars = [char if char.isalnum() else " " for char in normalized]
    return _SPACE_RE.sub(" ", "".join(chars)).strip()


def normalize_url_key(value: str) -> str:
    """Return a conservative equality key; do not merge HTTP and HTTPS."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return value.strip()
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def title_similarity(left: str, right: str) -> float:
    left_key = normalize_title(left)
    right_key = normalize_title(right)
    if not left_key or not right_key:
        return 0.0
    ratio = fuzz.ratio(left_key, right_key)
    token_sort = fuzz.token_sort_ratio(left_key, right_key)
    return round(max(ratio, token_sort), 2)


def _compact_title(value: str) -> str:
    return normalize_title(value).replace(" ", "")


def _content_key(body: str | None) -> str | None:
    if not body:
        return None
    normalized = _SPACE_RE.sub(" ", unicodedata.normalize("NFKC", body)).strip()
    if len(normalized) < 200:
        return None
    return hashlib.sha256(normalized.encode()).hexdigest()


def _identifier_values(doc: IntelDocument, kind: str) -> set[str]:
    raw = doc.identifiers.get(kind, [])
    if not isinstance(raw, list):
        return set()
    pattern = _IDENTIFIER_PATTERNS[kind]
    values = {str(value).upper() for value in raw if value}
    return {value for value in values if pattern.fullmatch(value)}


def _identifier_set(doc: IntelDocument) -> set[str]:
    return {value for kind in ("cve", "ghsa", "cnvd") for value in _identifier_values(doc, kind)}


def _identifiers_conflict(left: IntelDocument, right: IntelDocument) -> bool:
    left_ids = _identifier_set(left)
    right_ids = _identifier_set(right)
    return bool(left_ids and right_ids and left_ids.isdisjoint(right_ids))


def _dates_compatible(
    left: IntelDocument, right: IntelDocument, *, days: int, require_both: bool = False
) -> bool:
    if left.published_at is None or right.published_at is None:
        return not require_both
    return abs(left.published_at - right.published_at) <= timedelta(days=days)


def _blocking_keys(title: str) -> set[str]:
    normalized = normalize_title(title)
    keys = {f"w:{word}" for word in _WORD_RE.findall(normalized) if len(word) >= 4}
    for segment in _CJK_RE.findall(normalized):
        keys.update(f"c:{segment[index : index + 2]}" for index in range(len(segment) - 1))
    return keys


def _master_rank(doc: IntelDocument) -> tuple[int, float, int, int, int]:
    trust_rank = {"A": 0, "B": 1, "C": 2}.get(doc.trust_tier, 3)
    return (
        trust_rank,
        -doc.parse_quality,
        -len(doc.body or ""),
        -len(doc.title),
        doc.id,
    )


def deduplicate_documents(
    documents: list[IntelDocument],
    *,
    fuzzy_threshold: float = FUZZY_TITLE_THRESHOLD,
) -> dict[int, DedupDecision]:
    """Build non-destructive duplicate components and select one master each."""
    if not documents:
        return {}

    docs = {doc.id: doc for doc in documents}
    union_find = _UnionFind(list(docs))

    url_groups: dict[str, list[int]] = defaultdict(list)
    title_groups: dict[str, list[int]] = defaultdict(list)
    content_groups: dict[str, list[int]] = defaultdict(list)
    for doc in documents:
        if doc.canonical_url.strip():
            url_groups[normalize_url_key(doc.canonical_url)].append(doc.id)
        compact = _compact_title(doc.title)
        if len(compact) >= 20:
            title_groups[compact].append(doc.id)
        content_key = _content_key(doc.body)
        if content_key:
            content_groups[content_key].append(doc.id)

    for group in url_groups.values():
        if len(group) < 2:
            continue
        identified: dict[str, list[int]] = defaultdict(list)
        unidentified: list[int] = []
        for document_id in group:
            identifiers = _identifier_set(docs[document_id])
            if identifiers:
                for identifier in identifiers:
                    identified[identifier].append(document_id)
            else:
                unidentified.append(document_id)
        # A shared catalogue URL (for example CISA KEV) is not item identity.
        # Only documents sharing a strong identifier may merge in such groups.
        for same_identifier in identified.values():
            for document_id in same_identifier[1:]:
                union_find.union(same_identifier[0], document_id)
        for document_id in unidentified[1:]:
            union_find.union(unidentified[0], document_id)
        if len(identified) <= 1 and identified and unidentified:
            identified_master = next(iter(identified.values()))[0]
            union_find.union(identified_master, unidentified[0])

    for group in title_groups.values():
        for index, left_id in enumerate(group):
            for right_id in group[index + 1 :]:
                left = docs[left_id]
                right = docs[right_id]
                if not _identifiers_conflict(left, right) and _dates_compatible(
                    left, right, days=30
                ):
                    union_find.union(left_id, right_id)

    for group in content_groups.values():
        for index, left_id in enumerate(group):
            for right_id in group[index + 1 :]:
                left = docs[left_id]
                right = docs[right_id]
                if (
                    not _identifiers_conflict(left, right)
                    and _dates_compatible(left, right, days=30)
                    and title_similarity(left.title, right.title) >= 80
                ):
                    union_find.union(left_id, right_id)

    block_index: dict[str, list[int]] = defaultdict(list)
    for doc in documents:
        for key in _blocking_keys(doc.title):
            block_index[key].append(doc.id)

    candidate_pairs: set[tuple[int, int]] = set()
    for group in block_index.values():
        if len(group) > 100:
            continue
        for index, left_id in enumerate(group):
            for right_id in group[index + 1 :]:
                candidate_pairs.add((min(left_id, right_id), max(left_id, right_id)))

    for left_id, right_id in candidate_pairs:
        left = docs[left_id]
        right = docs[right_id]
        if _identifiers_conflict(left, right):
            continue
        if not _dates_compatible(left, right, days=14, require_both=True):
            continue
        left_len = len(_compact_title(left.title))
        right_len = len(_compact_title(right.title))
        if (
            min(left_len, right_len) < 24
            or min(left_len, right_len) / max(left_len, right_len) < 0.72
        ):
            continue
        ratio = fuzz.ratio(normalize_title(left.title), normalize_title(right.title))
        score = title_similarity(left.title, right.title)
        if score >= fuzzy_threshold and ratio >= 88:
            union_find.union(left_id, right_id)

    components: dict[int, list[IntelDocument]] = defaultdict(list)
    for doc in documents:
        components[union_find.find(doc.id)].append(doc)

    decisions: dict[int, DedupDecision] = {}
    for component in components.values():
        master = min(component, key=_master_rank)
        for doc in component:
            if doc.id == master.id:
                decisions[doc.id] = DedupDecision(doc.id, None, None, None)
                continue
            if normalize_url_key(doc.canonical_url) == normalize_url_key(master.canonical_url):
                kind, score = "exact_url", 1.0
            elif _compact_title(doc.title) == _compact_title(master.title):
                kind, score = "exact_title", 1.0
            elif _content_key(doc.body) and _content_key(doc.body) == _content_key(master.body):
                kind, score = "exact_content", 1.0
            else:
                kind = "near_title"
                score = title_similarity(doc.title, master.title) / 100
            decisions[doc.id] = DedupDecision(doc.id, master.id, kind, round(score, 4))
    return decisions


def strong_event_keys(doc: IntelDocument) -> tuple[EventKey, ...]:
    """Extract ordered, stable event keys; CWE is taxonomy, not event identity."""
    keys: list[EventKey] = []
    for kind in ("cve", "ghsa", "cnvd"):
        for value in sorted(_identifier_values(doc, kind)):
            keys.append(EventKey(f"{kind}:{value}", kind))
    match = _ARXIV_RE.search(doc.canonical_url)
    if match:
        keys.append(EventKey(f"arxiv:{match.group(1)}", "arxiv"))
    return tuple(keys)


def _primary_topic(documents: list[IntelDocument], kind: str) -> str | None:
    if kind in {"cve", "ghsa", "cnvd"}:
        return "cve"
    priority = ("security_for_ai", "ai_for_security", "agent", "llm", "system_security")
    counts = Counter(topic for doc in documents for topic in doc.tech_directions if topic != "cve")
    if not counts:
        return None
    return min(
        counts,
        key=lambda topic: (-counts[topic], priority.index(topic) if topic in priority else 99),
    )


def _event_type(documents: list[IntelDocument], kind: str) -> str | None:
    if kind in {"cve", "ghsa", "cnvd"}:
        return "vulnerability"
    if kind == "arxiv":
        return "research"
    counts = Counter(doc.event_type for doc in documents if doc.event_type)
    return counts.most_common(1)[0][0] if counts else None


def _summary(doc: IntelDocument) -> str | None:
    value = _SPACE_RE.sub(" ", doc.body or "").strip()
    if not value or value == doc.title.strip():
        return None
    return value[:600].rstrip()


def _event_score(documents: list[IntelDocument], *, kind: str, source_count: int) -> int:
    best_tier = min(
        (doc.trust_tier for doc in documents),
        key=lambda tier: {"A": 0, "B": 1, "C": 2}.get(tier, 3),
    )
    trust_score = {"A": 40, "B": 28, "C": 15}.get(best_tier, 10)
    identity_score = 25 if kind in {"cve", "ghsa", "cnvd"} else 15 if kind == "arxiv" else 5
    diversity_score = min(20, max(0, source_count - 1) * 7)
    quality_score = round(max((doc.parse_quality for doc in documents), default=0.0) * 15)
    return min(100, trust_score + identity_score + diversity_score + quality_score)


def build_event_drafts(
    documents: list[IntelDocument],
    decisions: dict[int, DedupDecision],
) -> dict[str, EventDraft]:
    """Turn duplicate components into strong-key or fallback events."""
    if not documents:
        return {}
    docs_by_id = {doc.id: doc for doc in documents}
    component_docs: dict[int, list[IntelDocument]] = defaultdict(list)
    for doc in documents:
        decision = decisions.get(doc.id)
        master_id = decision.near_dup_of if decision and decision.near_dup_of else doc.id
        component_docs[master_id].append(doc)

    event_members: dict[EventKey, dict[int, str]] = defaultdict(dict)
    for master_id, component in component_docs.items():
        keys_by_document = {doc.id: set(strong_event_keys(doc)) for doc in component}
        keys = {key for doc_keys in keys_by_document.values() for key in doc_keys}
        if len(keys) > 20:
            # Defensive degradation: a duplicate component must never create an
            # unbounded strong-key × document Cartesian product.
            for doc in component:
                own_keys = keys_by_document[doc.id]
                if not own_keys:
                    own_keys = {EventKey(f"document:{doc.id}", "document")}
                for key in own_keys:
                    event_members[key][doc.id] = (
                        f"identifier:{key.kind}" if key.kind != "document" else "component"
                    )
            continue
        if not keys:
            keys = {EventKey(f"document:{master_id}", "document")}
        for key in keys:
            for doc in component:
                if key in keys_by_document[doc.id]:
                    reason = f"identifier:{key.kind}"
                else:
                    decision = decisions.get(doc.id)
                    reason = (
                        decision.duplicate_kind
                        if decision and decision.duplicate_kind
                        else "component"
                    )
                event_members[key][doc.id] = reason

    drafts: dict[str, EventDraft] = {}
    for key, reasons in event_members.items():
        members = [docs_by_id[document_id] for document_id in reasons]
        primary = min(members, key=_master_rank)
        evidence_level = min(
            (doc.trust_tier for doc in members),
            key=lambda tier: {"A": 0, "B": 1, "C": 2}.get(tier, 3),
        )
        observed = [doc.published_at or doc.fetched_at for doc in members]
        observed = [value for value in observed if value is not None]
        source_count = len({doc.source_id for doc in members})
        title = primary.title.strip()[:240]
        memberships = tuple(
            EventMembership(doc.id, doc.trust_tier, reasons[doc.id])
            for doc in sorted(members, key=lambda item: item.id)
        )
        drafts[key.fingerprint] = EventDraft(
            fingerprint=key.fingerprint,
            event_type=_event_type(members, key.kind),
            topic=_primary_topic(members, key.kind),
            title=title,
            summary=_summary(primary),
            status="detected",
            score=_event_score(members, kind=key.kind, source_count=source_count),
            evidence_level=evidence_level,
            first_seen_at=min(observed) if observed else None,
            last_seen_at=max(observed) if observed else None,
            memberships=memberships,
        )
    return drafts
